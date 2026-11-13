//! Persistance de l'apprentissage sur disque (pattern Repository) : le reste du module
//! manipule des structures, ce fichier seul sait où et comment elles sont écrites.
//!
//! ```text
//! <data_dir>/
//! ├── state.json        destinations vues, exceptions, version active… (petit, réécrit s'il change)
//! ├── samples.jsonl     journal des échantillons : ajouts et changements de statut (ajout seul,
//! │                     réécrit en entier quand il devient trop long)
//! ├── decisions.jsonl   journal des décisions, une ligne JSON par décision (ajout seul)
//! └── models/v<N>.json  modèles validés, pour le retour arrière
//! ```
//!
//! Les échantillons sont la partie volumineuse (jusqu'à `max_samples` fenêtres, des dizaines
//! de Mo) : les réécrire à chaque sauvegarde userait inutilement une carte SD.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Serialize, de::DeserializeOwned};

use super::model::Model;

pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    /// Ouvre (et crée si besoin) le dossier de données.
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir.join("models")).with_context(|| format!("création de {}", dir.display()))?;
        Ok(Self { dir: dir.to_path_buf() })
    }

    #[cfg(test)]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// État enregistré, ou `None` au premier lancement.
    pub fn load_state<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        let path = self.dir.join("state.json");
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path).with_context(|| format!("lecture de {}", path.display()))?;
        serde_json::from_slice(&raw).map(Some).with_context(|| format!("contenu invalide dans {}", path.display()))
    }

    /// Écrit l'état de façon atomique : fichier temporaire puis renommage, pour qu'un arrêt
    /// brutal ne laisse jamais un état à moitié écrit.
    pub fn save_state(&self, bytes: &[u8]) -> Result<()> {
        let tmp = self.dir.join("state.json.tmp");
        fs::write(&tmp, bytes).with_context(|| format!("écriture de {}", tmp.display()))?;
        fs::rename(&tmp, self.dir.join("state.json")).context("remplacement de state.json")
    }

    /// Lignes du journal des échantillons, ou `None` s'il n'existe pas encore. Une ligne
    /// illisible (dernière ligne coupée par un arrêt brutal) est ignorée, pas fatale.
    pub fn load_samples<T: DeserializeOwned>(&self) -> Result<Option<Vec<T>>> {
        let path = self.dir.join("samples.jsonl");
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).with_context(|| format!("lecture de {}", path.display()))?;
        let mut bad = 0;
        let items = raw.lines().filter(|l| !l.is_empty()).filter_map(|l| serde_json::from_str(l).map_err(|_| bad += 1).ok()).collect();
        if bad > 0 {
            tracing::warn!("{bad} ligne(s) illisible(s) ignorée(s) dans {}", path.display());
        }
        Ok(Some(items))
    }

    /// Ajoute des lignes au journal des échantillons.
    pub fn append_samples<T: Serialize>(&self, items: &[T]) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        let f = OpenOptions::new().create(true).append(true).open(self.dir.join("samples.jsonl")).context("ouverture de samples.jsonl")?;
        write_lines(f, items).context("écriture de samples.jsonl")
    }

    /// Remplace tout le journal des échantillons (compaction), de façon atomique.
    pub fn rewrite_samples<T: Serialize>(&self, items: &[T]) -> Result<()> {
        let tmp = self.dir.join("samples.jsonl.tmp");
        write_lines(fs::File::create(&tmp).with_context(|| format!("création de {}", tmp.display()))?, items)
            .with_context(|| format!("écriture de {}", tmp.display()))?;
        fs::rename(&tmp, self.dir.join("samples.jsonl")).context("remplacement de samples.jsonl")
    }

    fn model_path(&self, version: u32) -> PathBuf {
        self.dir.join("models").join(format!("v{version}.json"))
    }

    pub fn save_model(&self, m: &Model) -> Result<()> {
        let path = self.model_path(m.version);
        fs::write(&path, serde_json::to_vec(m)?).with_context(|| format!("écriture de {}", path.display()))
    }

    pub fn load_model(&self, version: u32) -> Result<Model> {
        let path = self.model_path(version);
        let raw = fs::read(&path).with_context(|| format!("modèle v{version} introuvable ({})", path.display()))?;
        serde_json::from_slice(&raw).with_context(|| format!("contenu invalide dans {}", path.display()))
    }

    /// Versions enregistrées, de la plus ancienne à la plus récente.
    pub fn versions(&self) -> Vec<u32> {
        let mut v: Vec<u32> = fs::read_dir(self.dir.join("models"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.strip_prefix('v')?.strip_suffix(".json")?.parse().ok())
            .collect();
        v.sort_unstable();
        v
    }

    /// Garde les `keep` versions les plus récentes, plus `protect` (version active), et supprime
    /// les autres. La version protégée ne compte pas dans le quota.
    pub fn prune_models(&self, keep: usize, protect: u32) {
        let others: Vec<u32> = self.versions().into_iter().filter(|&v| v != protect).collect();
        let excess = others.len().saturating_sub(keep);
        for v in others.into_iter().take(excess) {
            let _ = fs::remove_file(self.model_path(v));
        }
    }

    /// Ajoute une entrée au journal des décisions.
    pub fn append_decision<T: Serialize>(&self, entry: &T) -> Result<()> {
        let mut f = OpenOptions::new().create(true).append(true).open(self.dir.join("decisions.jsonl"))?;
        writeln!(f, "{}", serde_json::to_string(entry)?)?;
        Ok(())
    }
}

/// Écrit une ligne JSON par élément, avec un tampon (une écriture système par bloc, pas par ligne).
fn write_lines<T: Serialize>(f: fs::File, items: &[T]) -> Result<()> {
    let mut w = std::io::BufWriter::new(f);
    for item in items {
        serde_json::to_writer(&mut w, item)?;
        w.write_all(b"\n")?;
    }
    w.flush()?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Dossier temporaire propre à un test (supprimé s'il existait déjà).
    pub fn temp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cyward-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    // Un état écrit puis relu est identique, et l'absence d'état renvoie None.
    #[test]
    fn state_roundtrip() {
        let s = Storage::open(&temp_dir("state")).unwrap();
        assert!(s.load_state::<Vec<u32>>().unwrap().is_none());
        s.save_state(&serde_json::to_vec(&vec![1u32, 2, 3]).unwrap()).unwrap();
        assert_eq!(s.load_state::<Vec<u32>>().unwrap(), Some(vec![1, 2, 3]));
    }

    // Journal des échantillons : absent au départ, les ajouts s'accumulent, la réécriture remplace tout.
    #[test]
    fn samples_journal_appends_then_rewrites() {
        let s = Storage::open(&temp_dir("samples")).unwrap();
        assert!(s.load_samples::<u32>().unwrap().is_none());
        s.append_samples(&[1u32, 2]).unwrap();
        s.append_samples(&[3u32]).unwrap();
        assert_eq!(s.load_samples::<u32>().unwrap(), Some(vec![1, 2, 3]));
        s.rewrite_samples(&[9u32]).unwrap();
        assert_eq!(s.load_samples::<u32>().unwrap(), Some(vec![9]));
    }

    // Une dernière ligne coupée (arrêt brutal pendant l'ajout) n'empêche pas de relire le reste.
    #[test]
    fn truncated_journal_line_is_skipped() {
        let s = Storage::open(&temp_dir("truncated")).unwrap();
        s.append_samples(&[1u32, 2]).unwrap();
        OpenOptions::new().append(true).open(s.dir().join("samples.jsonl")).unwrap().write_all(b"[1, 2").unwrap();
        assert_eq!(s.load_samples::<u32>().unwrap(), Some(vec![1, 2]));
    }

    // Le nettoyage garde les versions récentes et ne supprime jamais la version protégée.
    #[test]
    fn prune_keeps_recent_and_protected() {
        let s = Storage::open(&temp_dir("prune")).unwrap();
        for v in 1..=5 {
            fs::write(s.model_path(v), "{}").unwrap();
        }
        s.prune_models(2, 1);
        assert_eq!(s.versions(), vec![1, 4, 5]);
    }

    // Le journal ajoute une ligne par décision.
    #[test]
    fn journal_appends_lines() {
        let s = Storage::open(&temp_dir("journal")).unwrap();
        s.append_decision(&"a").unwrap();
        s.append_decision(&"b").unwrap();
        assert_eq!(fs::read_to_string(s.dir().join("decisions.jsonl")).unwrap().lines().count(), 2);
    }
}
