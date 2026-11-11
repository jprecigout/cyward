//! Détecteur d'anomalies de comportement (pattern Strategy) : alimente l'apprentissage du
//! comportement normal (`crate::anomaly`) et signale les fenêtres qu'il juge anormales.
//!
//! Pour chaque machine interne, les paquets d'une fenêtre de `window_secs` sont résumés en
//! compteurs. À la fin de la fenêtre, ils deviennent 12 caractéristiques, enregistrées et
//! jugées par le modèle actif. Une anomalie lève une alerte `host_anomaly` qui demande à
//! l'utilisateur si la situation est normale.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
};

use chrono::{DateTime, Local, Timelike};
use serde_json::json;

use super::{Detector, dns::shannon_entropy, ts_to_dt};
use crate::{
    alert::{Alert, AlertKind, AlertSource, Severity},
    anomaly::{
        baseline::{Baseline, WindowVerdict},
        features::{self, HostCounters, MAX_DSTS, MAX_PORTS},
    },
    capture::PacketMeta,
    config::{AnomalyMode, DetectionConfig},
};

/// Machines suivies au plus par fenêtre (borne mémoire face à des adresses usurpées).
const MAX_HOSTS: usize = 10_000;

pub struct HostAnomaly {
    baseline: Arc<Baseline>,
    net: DetectionConfig,
    /// Début de la fenêtre en cours (None avant le premier paquet).
    start: Option<f64>,
    hosts: HashMap<IpAddr, HostCounters>,
}

impl HostAnomaly {
    pub fn new(baseline: Arc<Baseline>, net: DetectionConfig) -> Self {
        Self { baseline, net, start: None, hosts: HashMap::new() }
    }

    fn window(&self) -> f64 {
        self.baseline.config().window_secs
    }

    /// Compteurs de la machine, ou None si le plafond de machines suivies est atteint.
    fn counters(&mut self, ip: IpAddr) -> Option<&mut HostCounters> {
        if !self.hosts.contains_key(&ip) && self.hosts.len() >= MAX_HOSTS {
            return None;
        }
        Some(self.hosts.entry(ip).or_default())
    }

    /// Clôt la fenêtre en cours si `now` l'a dépassée. Les fenêtres sans aucun trafic ne
    /// produisent pas d'échantillon : l'absence d'activité n'est pas une anomalie ici.
    fn roll(&mut self, now: f64, out: &mut Vec<Alert>) {
        let Some(start) = self.start else {
            self.start = Some(now);
            return;
        };
        let w = self.window();
        if now - start >= w {
            self.close(start, start + w, out);
            self.start = Some(start + ((now - start) / w).floor() * w);
        }
    }

    /// Transforme les compteurs de chaque machine en échantillon et fait juger chacun.
    fn close(&mut self, start: f64, end: f64, out: &mut Vec<Alert>) {
        let hour = local_hour(start);
        // Ordre stable des machines : l'ordre d'enregistrement des échantillons, donc le
        // modèle appris, ne dépend pas de l'ordre interne de la table.
        let mut hosts: Vec<(IpAddr, HostCounters)> = self.hosts.drain().collect();
        hosts.sort_by_key(|(ip, _)| *ip);
        for (ip, c) in hosts {
            let host = ip.to_string();
            let dsts: Vec<String> = c.dsts.iter().map(|d| d.to_string()).collect();
            let new = self.baseline.new_destinations(&host, dsts.iter().map(String::as_str));
            let f = features::compute(&c, new, hour);
            if let WindowVerdict::Anomaly(info) = self.baseline.record_window(&host, start, end, f) {
                out.push(anomaly_alert(&host, start, end, &info, self.baseline.config().mode));
            }
        }
    }
}

impl Detector for HostAnomaly {
    fn on_packet(&mut self, p: &PacketMeta, out: &mut Vec<Alert>) {
        self.roll(p.ts, out);
        let (src_local, dst_local) = (self.net.is_local(&p.src), self.net.is_local(&p.dst));
        if src_local && let Some(c) = self.counters(p.src) {
            c.bytes_out += u64::from(p.len);
            c.packets_out += 1;
            if !dst_local {
                c.bytes_out_external += u64::from(p.len);
            }
            if p.tcp.is_connection_start() {
                c.conn_out += 1;
                if c.dports.len() < MAX_PORTS {
                    c.dports.insert(p.dport);
                }
            }
            if c.dsts.len() < MAX_DSTS {
                c.dsts.insert(p.dst);
            }
            if let Some(q) = &p.dns_query {
                c.dns_queries += 1;
                c.dns_entropy_sum += shannon_entropy(q.split('.').max_by_key(|l| l.len()).unwrap_or(""));
            }
        }
        if dst_local && p.dst != p.src && let Some(c) = self.counters(p.dst) {
            c.bytes_in += u64::from(p.len);
        }
    }

    fn tick(&mut self, now: f64, out: &mut Vec<Alert>) {
        self.roll(now, out);
    }
}

/// Heure locale (décimale) d'un horodatage : les habitudes suivent l'heure du lieu, pas l'UTC.
fn local_hour(ts: f64) -> f64 {
    let t = DateTime::from_timestamp(ts as i64, 0).unwrap_or_default().with_timezone(&Local);
    f64::from(t.hour()) + f64::from(t.minute()) / 60.0
}

/// Alerte d'anomalie. Elle couvre la fenêtre [start, end) : des fenêtres anormales
/// consécutives d'une même machine fusionnent en une seule alerte (même empreinte, et la
/// suivante commence là où la précédente finit), à laquelle l'utilisateur répond une fois.
fn anomaly_alert(host: &str, start: f64, end: f64, info: &crate::anomaly::baseline::AnomalyInfo, mode: AnomalyMode) -> Alert {
    let severity = match mode {
        AnomalyMode::Observation => Severity::Info,
        AnomalyMode::Alert => Severity::Medium,
    };
    let main = info
        .deviations
        .iter()
        .map(|d| format!("{} : {} ({})", features::NAMES[d.index], d.value, d.reference))
        .collect::<Vec<_>>()
        .join(" ; ");
    let mut a = Alert::new(AlertKind::HostAnomaly, severity, AlertSource::Network, ts_to_dt(start), format!("Comportement inhabituel de {host}"))
        .description(format!(
            "Score d'anomalie {:.2} (seuil {:.2}, modèle v{}). Principaux écarts : {main}. Est-ce normal ? Répondez dans le dashboard : le modèle n'apprendra cette période que si vous la confirmez.",
            info.score, info.threshold, info.version
        ))
        .src(host)
        .fingerprint(format!("anomaly|{host}"))
        .evidence(json!({
            "host": host,
            "window_start": start,
            "window_end": end,
            "score": info.score,
            "threshold": info.threshold,
            "model_version": info.version,
            "deviations": info.deviations.iter().map(|d| json!({ "feature": features::NAMES[d.index], "value": d.value, "usual": d.usual, "reference": d.reference, "z": d.z })).collect::<Vec<_>>(),
            "feature_ids": info.deviations.iter().map(|d| d.index).collect::<Vec<_>>(),
        }));
    a.last_seen = ts_to_dt(end);
    a
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::{
        anomaly::model::Sample,
        config::AnomalyConfig,
        detect::testutil::syn,
    };

    fn baseline(mode: AnomalyMode) -> Arc<Baseline> {
        Arc::new(Baseline::in_memory(AnomalyConfig { enabled: true, mode, window_secs: 60.0, min_training_samples: 50, ..Default::default() }))
    }

    /// Simule `minutes` minutes de trafic régulier : quelques connexions HTTPS par minute.
    fn regular(d: &mut HostAnomaly, out: &mut Vec<Alert>, from_min: usize, minutes: usize) {
        for m in from_min..from_min + minutes {
            for k in 0..(3 + m % 3) {
                let mut p = syn(m as f64 * 60.0 + k as f64 * 7.0, "192.168.1.20", "203.0.113.10", 443);
                p.len = 1500 + (m * 37 % 400) as u32;
                d.on_packet(&p, out);
            }
        }
    }

    // Sans modèle actif, les fenêtres sont seulement enregistrées (une par minute et par machine).
    #[test]
    fn windows_are_recorded_while_learning() {
        let b = baseline(AnomalyMode::Observation);
        let mut d = HostAnomaly::new(b.clone(), DetectionConfig::default());
        let mut out = Vec::new();
        regular(&mut d, &mut out, 0, 30);
        assert!(out.is_empty());
        // 29 fenêtres closes (la dernière est encore ouverte).
        assert_eq!(b.status().samples.normal, 29);
    }

    // Avec un modèle validé, une rafale de connexions vers de nombreuses destinations lève
    // une alerte `info` en mode observation, couvrant sa fenêtre et expliquée par ses écarts.
    #[test]
    fn burst_is_reported_after_training() {
        let b = baseline(AnomalyMode::Observation);
        let mut d = HostAnomaly::new(b.clone(), DetectionConfig::default());
        let mut out = Vec::new();
        regular(&mut d, &mut out, 0, 120);
        let never = |_: &Sample| false;
        b.train(&never, Utc::now()).unwrap();
        let hosts: Vec<String> = b.status().candidate.unwrap().diff.hosts.iter().map(|h| h.host.clone()).collect();
        b.decide(&hosts, &[], Utc::now()).unwrap();

        // Minute 121 : 300 connexions vers 300 destinations distinctes.
        for k in 0..300u32 {
            let p = syn(121.0 * 60.0 + f64::from(k) * 0.1, "192.168.1.20", &format!("198.51.100.{}", k % 250), 8000 + (k % 50) as u16);
            d.on_packet(&p, &mut out);
        }
        d.tick(123.0 * 60.0, &mut out);
        let a = out.iter().find(|a| a.kind == AlertKind::HostAnomaly).expect("anomalie attendue");
        assert_eq!(a.severity, Severity::Info);
        assert_eq!(a.src.as_deref(), Some("192.168.1.20"));
        assert!(a.last_seen > a.first_seen);
        assert!(!a.evidence["feature_ids"].as_array().unwrap().is_empty());
    }

    // Le mode « alert » produit des alertes de sévérité moyenne (envoyées au LLM).
    #[test]
    fn alert_mode_uses_medium_severity() {
        let info = crate::anomaly::baseline::AnomalyInfo { score: 0.8, threshold: 0.6, version: 3, deviations: vec![] };
        assert_eq!(anomaly_alert("10.0.0.1", 0.0, 60.0, &info, AnomalyMode::Alert).severity, Severity::Medium);
    }
}
