//! Déclenchement des apprentissages et alertes qui en découlent.
//!
//! - Toutes les 10 minutes : l'état est sauvegardé, puis un apprentissage est lancé si le
//!   moment est venu (fin de la période d'observation, ou intervalle de réapprentissage écoulé).
//! - Avant d'apprendre, les fenêtres des machines visées par une alerte **à règles** (scan,
//!   force brute, C2…) sont exclues : on n'apprend jamais pendant une attaque détectée.
//! - Un candidat présentant une dérive cumulée lève une alerte ; une machine refusée lors
//!   d'une validation aussi.
//!
//! L'apprentissage est coûteux en calcul : il tourne dans un thread bloquant dédié, jamais
//! dans la boucle asynchrone qui sert le dashboard.

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::Result;
use chrono::Utc;
use serde_json::json;

use super::{
    baseline::{Baseline, TrainOutcome},
    model::Sample,
};
use crate::alert::{Alert, AlertKind, AlertSink, AlertSource, Severity};

/// Intervalle entre deux vérifications (sauvegarde + apprentissage éventuel).
const CHECK_EVERY: Duration = Duration::from_secs(600);

/// Lance la tâche de fond de l'apprentissage.
pub fn spawn(baseline: Arc<Baseline>, sink: AlertSink) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(CHECK_EVERY);
        ticker.tick().await; // le premier tick est immédiat : on laisse d'abord l'agent démarrer
        loop {
            ticker.tick().await;
            save(&baseline).await;
            if baseline.should_train(Utc::now()) {
                match run_training(baseline.clone(), sink.clone()).await {
                    Ok(o) => tracing::info!("apprentissage du comportement normal : {o:?}"),
                    Err(e) => tracing::warn!("apprentissage du comportement normal : {e:#}"),
                }
            }
        }
    });
}

/// Apprend maintenant (tâche périodique ou demande de l'utilisateur), lève les alertes de
/// dérive, et sauvegarde.
pub async fn run_training(baseline: Arc<Baseline>, sink: AlertSink) -> Result<TrainOutcome> {
    let tainted = tainted_by_rules(&sink.store.list(usize::MAX));
    let b = baseline.clone();
    let outcome = tokio::task::spawn_blocking(move || b.train(&tainted, Utc::now())).await??;
    if let TrainOutcome::PendingReview { version, drift_hosts, .. } = &outcome {
        for host in drift_hosts {
            sink.emit(
                Alert::new(AlertKind::BaselineDrift, Severity::High, AlertSource::Network, Utc::now(), format!("Dérive du comportement de {host}"))
                    .description(format!(
                        "Le modèle candidat v{version} accepterait pour {host} des volumes très éloignés de ceux du premier modèle validé. Un changement aussi important, installé progressivement, peut aussi être un empoisonnement de l'apprentissage. Vérifiez le diff avant de l'accepter."
                    ))
                    .src(host)
                    .fingerprint(format!("drift|{host}|{version}"))
                    .evidence(json!({ "host": host, "candidate_version": version })),
            );
        }
    }
    save(&baseline).await;
    Ok(outcome)
}

/// Sauvegarde dans un thread bloquant (écriture disque, compaction parfois volumineuse),
/// hors de la boucle asynchrone. Une erreur est journalisée : la suivante réessaiera.
pub async fn save(baseline: &Arc<Baseline>) {
    let b = baseline.clone();
    match tokio::task::spawn_blocking(move || b.save()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::error!("sauvegarde de l'apprentissage : {e:#}"),
        Err(e) => tracing::error!("sauvegarde de l'apprentissage interrompue : {e}"),
    }
}

/// Lève une alerte par machine dont le nouveau comportement a été refusé.
pub fn emit_rejected(sink: &AlertSink, rejected: &[String], version: Option<u32>) {
    for host in rejected {
        sink.emit(
            Alert::new(AlertKind::BaselineRejected, Severity::High, AlertSource::Network, Utc::now(), format!("Changement de comportement refusé pour {host}"))
                .description(format!(
                    "Lors de la validation du modèle{}, le nouveau comportement de {host} a été refusé : ses fenêtres concernées sont marquées suspectes et ne seront jamais apprises. Il reste à comprendre ce qui l'a causé.",
                    version.map(|v| format!(" v{v}")).unwrap_or_default()
                ))
                .src(host)
                .evidence(json!({ "host": host, "model_version": version })),
        );
    }
}

/// Construit le filtre des fenêtres à ne pas apprendre : celles d'une machine source ou cible
/// d'une alerte à règles, sur une période qui chevauche l'alerte.
pub fn tainted_by_rules(alerts: &[Alert]) -> impl Fn(&Sample) -> bool + Send + 'static {
    let mut periods: HashMap<String, Vec<(f64, f64)>> = HashMap::new();
    for a in alerts.iter().filter(|a| !a.kind.is_learning()) {
        let span = (a.first_seen.timestamp() as f64, a.last_seen.timestamp() as f64);
        for who in [a.src.as_deref(), a.dst.as_deref()].into_iter().flatten() {
            periods.entry(host_part(who).to_string()).or_default().push(span);
        }
    }
    move |s: &Sample| periods.get(&s.host).is_some_and(|p| p.iter().any(|&(from, to)| from <= s.end && to >= s.start))
}

/// Retire le port d'une adresse « hôte:port » (les IPv6, à plusieurs « : », sont laissées intactes).
fn host_part(s: &str) -> &str {
    if s.matches(':').count() == 1 { s.split(':').next().unwrap_or(s) } else { s }
}

#[cfg(test)]
mod tests {
    use chrono::DateTime;

    use super::*;
    use crate::anomaly::model::tests::sample;

    fn alert(kind: AlertKind, src: &str, dst: &str, from: i64, to: i64) -> Alert {
        let mut a = Alert::new(kind, Severity::High, AlertSource::Network, DateTime::from_timestamp(from, 0).unwrap(), "t").src(src).dst(dst);
        a.last_seen = DateTime::from_timestamp(to, 0).unwrap();
        a
    }

    // Une alerte à règles exclut les fenêtres qui la chevauchent, pour sa source comme pour sa
    // cible (port retiré), et pas les autres périodes ni les autres machines.
    #[test]
    fn rule_alerts_taint_overlapping_windows() {
        let t = tainted_by_rules(&[alert(AlertKind::BruteForce, "203.0.113.7", "10.0.0.1:22", 3000, 3100)]);
        let s = sample("10.0.0.1", 10, 1.0); // fenêtre 3000–3300
        assert!(t(&s));
        assert!(!t(&sample("10.0.0.1", 20, 1.0)));
        assert!(!t(&sample("10.0.0.2", 10, 1.0)));
        let attacker = Sample { host: "203.0.113.7".into(), ..s };
        assert!(t(&attacker));
    }

    // Les alertes de l'apprentissage lui-même n'excluent rien (sinon une anomalie empêcherait
    // à jamais d'apprendre la fenêtre, même confirmée normale).
    #[test]
    fn learning_alerts_do_not_taint() {
        let t = tainted_by_rules(&[alert(AlertKind::HostAnomaly, "10.0.0.1", "", 3000, 3100)]);
        assert!(!t(&sample("10.0.0.1", 10, 1.0)));
    }
}
