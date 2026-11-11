//! Isolation Forest (Liu, Ting et Zhou, 2008), implémenté sans dépendance.
//!
//! Principe : on construit des arbres en coupant les données au hasard (une caractéristique
//! au hasard, une valeur de coupure au hasard entre son minimum et son maximum). Un point
//! atypique est isolé en peu de coupures, donc près de la racine. Le score d'un point dépend
//! de la profondeur moyenne à laquelle il est isolé dans l'ensemble des arbres.
//!
//! Le générateur aléatoire est interne et initialisé par une graine : même graine et mêmes
//! données donnent le même modèle, ce qui rend les tests et les réapprentissages reproductibles.

use serde::{Deserialize, Serialize};

/// Constante d'Euler-Mascheroni, pour approcher les nombres harmoniques.
const EULER_GAMMA: f64 = 0.577_215_664_9;

/// Forêt entraînée. Sérialisable pour être enregistrée avec le modèle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IsolationForest {
    trees: Vec<Tree>,
    /// Taille effective des sous-échantillons ; sert à normaliser le score.
    sample_size: usize,
}

/// Arbre stocké à plat : les enfants sont référencés par leur indice dans `nodes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Tree {
    nodes: Vec<Node>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum Node {
    /// Feuille : `size` points n'ont pas été séparés (profondeur maximale atteinte ou valeurs égales).
    Leaf { size: usize },
    /// Coupure : à gauche si `x[feature] < value`, sinon à droite. `min` et `max` sont les
    /// bornes des valeurs vues à ce nœud pendant l'apprentissage (voir `path_length`).
    Split { feature: usize, value: f64, min: f64, max: f64, left: usize, right: usize },
}

impl IsolationForest {
    /// Entraîne `n_trees` arbres sur des sous-échantillons de `sample_size` points.
    /// Toutes les lignes de `data` doivent avoir la même longueur.
    pub fn fit<R: AsRef<[f64]>>(data: &[R], n_trees: usize, sample_size: usize, seed: u64) -> Self {
        let rows: Vec<&[f64]> = data.iter().map(|r| r.as_ref()).collect();
        let psi = sample_size.min(rows.len()).max(1);
        // Profondeur maximale : au-delà, un point n'est plus « facile à isoler » et le détail est inutile.
        let limit = (psi as f64).log2().ceil().max(1.0) as usize;
        let mut rng = SplitMix64::new(seed);
        let trees = (0..n_trees)
            .map(|_| {
                let idx = rng.sample_indices(rows.len(), psi);
                let mut nodes = Vec::new();
                build(&mut nodes, &rows, idx, 0, limit, &mut rng);
                Tree { nodes }
            })
            .collect();
        Self { trees, sample_size: psi }
    }

    /// Score d'anomalie entre 0 et 1 : proche de 1 = isolé très vite (atypique),
    /// autour de 0,5 ou moins = comparable au reste des données.
    pub fn score(&self, x: &[f64]) -> f64 {
        if self.trees.is_empty() {
            return 0.0;
        }
        let mean = self.trees.iter().map(|t| t.path_length(x)).sum::<f64>() / self.trees.len() as f64;
        let norm = average_path(self.sample_size);
        if norm == 0.0 { 0.0 } else { 2f64.powf(-mean / norm) }
    }
}

impl Tree {
    /// Profondeur à laquelle `x` atteint une feuille, corrigée par la profondeur moyenne
    /// qu'il aurait fallu pour séparer les points restés ensemble dans cette feuille.
    ///
    /// Écart à l'algorithme d'origine : une valeur **hors de la plage** vue à un nœud est
    /// considérée comme isolée à ce nœud. Sans cela, un point très au-delà des données
    /// (100 fois plus d'octets que d'habitude) suit les points extrêmes et reste mélangé à
    /// eux : c'est le « masquage », d'autant plus fort que les valeurs se répètent.
    fn path_length(&self, x: &[f64]) -> f64 {
        let mut i = 0;
        let mut depth = 0.0;
        loop {
            match self.nodes[i] {
                Node::Leaf { size } => return depth + average_path(size),
                Node::Split { feature, min, max, .. } if x[feature] < min || x[feature] > max => return depth + 1.0,
                Node::Split { feature, value, left, right, .. } => {
                    i = if x[feature] < value { left } else { right };
                    depth += 1.0;
                }
            }
        }
    }
}

/// Construit récursivement un sous-arbre à partir des points `idx` ; renvoie l'indice de sa racine.
fn build(nodes: &mut Vec<Node>, rows: &[&[f64]], idx: Vec<usize>, depth: usize, limit: usize, rng: &mut SplitMix64) -> usize {
    let id = nodes.len();
    // Réserve la place du nœud avant ses enfants, pour que `id` reste son indice.
    nodes.push(Node::Leaf { size: idx.len() });
    if depth >= limit || idx.len() <= 1 {
        return id;
    }
    let dims = rows[idx[0]].len();
    // Quelques essais pour trouver une caractéristique qui varie dans ce groupe ;
    // si toutes sont constantes, le nœud reste une feuille.
    for _ in 0..dims {
        let feature = rng.below(dims);
        let (min, max) = idx.iter().fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &i| {
            let v = rows[i][feature];
            (lo.min(v), hi.max(v))
        });
        if max > min {
            let value = min + rng.unit() * (max - min);
            let (l, r): (Vec<usize>, Vec<usize>) = idx.iter().partition(|&&i| rows[i][feature] < value);
            let left = build(nodes, rows, l, depth + 1, limit, rng);
            let right = build(nodes, rows, r, depth + 1, limit, rng);
            nodes[id] = Node::Split { feature, value, min, max, left, right };
            return id;
        }
    }
    id
}

/// Profondeur moyenne d'une recherche infructueuse dans un arbre binaire de `n` points :
/// c(n) = 2·H(n−1) − 2(n−1)/n. Sert de référence pour normaliser les profondeurs.
fn average_path(n: usize) -> f64 {
    match n {
        0 | 1 => 0.0,
        2 => 1.0,
        _ => {
            let n = n as f64;
            2.0 * ((n - 1.0).ln() + EULER_GAMMA) - 2.0 * (n - 1.0) / n
        }
    }
}

/// Générateur pseudo-aléatoire SplitMix64 : rapide, de bonne qualité statistique, et
/// reproductible à partir d'une graine. Pas d'usage cryptographique.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Entier dans [0, n).
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    /// Réel dans [0, 1), à partir des 53 bits de poids fort.
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// `k` indices distincts tirés dans [0, n) (mélange de Fisher-Yates partiel).
    fn sample_indices(&mut self, n: usize, k: usize) -> Vec<usize> {
        let mut all: Vec<usize> = (0..n).collect();
        for i in 0..k.min(n) {
            let j = i + self.below(n - i);
            all.swap(i, j);
        }
        all.truncate(k.min(n));
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Nuage régulier de 400 points autour de (10, 10).
    fn cloud() -> Vec<[f64; 2]> {
        (0..400).map(|i| [10.0 + (i % 20) as f64 * 0.1, 10.0 + (i / 20) as f64 * 0.1]).collect()
    }

    // Un point loin du nuage est isolé plus vite, donc mieux noté, qu'un point du nuage.
    #[test]
    fn outlier_scores_higher_than_inliers() {
        let f = IsolationForest::fit(&cloud(), 100, 256, 42);
        let inlier = f.score(&[11.0, 11.0]);
        let outlier = f.score(&[30.0, -5.0]);
        assert!(outlier > 0.6, "outlier = {outlier}");
        assert!(inlier < 0.55, "inlier = {inlier}");
        assert!(outlier > inlier + 0.15);
    }

    // Même graine et mêmes données : exactement les mêmes scores.
    #[test]
    fn same_seed_same_model() {
        let a = IsolationForest::fit(&cloud(), 50, 128, 7);
        let b = IsolationForest::fit(&cloud(), 50, 128, 7);
        assert_eq!(a.score(&[12.0, 9.0]), b.score(&[12.0, 9.0]));
    }

    // Le modèle relu depuis JSON donne les mêmes scores que l'original.
    #[test]
    fn serde_roundtrip_keeps_scores() {
        let f = IsolationForest::fit(&cloud(), 20, 64, 1);
        let g: IsolationForest = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(f.score(&[15.0, 3.0]), g.score(&[15.0, 3.0]));
    }

    // Des données toutes identiques ne font pas paniquer la construction (aucune coupure possible).
    #[test]
    fn constant_data_is_handled() {
        let f = IsolationForest::fit(&vec![[1.0, 1.0]; 50], 10, 32, 3);
        let s = f.score(&[1.0, 1.0]);
        assert!(s.is_finite());
    }

    // Les indices tirés sont distincts et dans l'intervalle demandé.
    #[test]
    fn sample_indices_are_distinct() {
        let mut rng = SplitMix64::new(9);
        let mut v = rng.sample_indices(100, 30);
        assert_eq!(v.len(), 30);
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), 30);
        assert!(v.iter().all(|&i| i < 100));
    }
}
