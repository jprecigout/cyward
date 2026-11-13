//! Apprentissage du comportement normal du réseau, avec validation humaine.
//!
//! Chaque machine interne est décrite, fenêtre après fenêtre, par 12 caractéristiques
//! ([`features`]). Un Isolation Forest ([`iforest`]) apprend ces profils et signale ce qui
//! s'en écarte. Rien n'entre dans le comportement normal sans l'accord de l'utilisateur :
//! chaque anomalie pose la question « est-ce normal ? », et chaque nouveau modèle est
//! comparé à l'actif ([`diff`]) avant d'être validé. [`baseline`] porte ces règles,
//! [`storage`] les persiste, [`trainer`] déclenche les apprentissages.
//!
//! Conception complète : docs/conception-normalite.md.
//!
//! Ce module ne dépend ni de `detect`, ni de `llm`, ni de `web` : le détecteur
//! (`detect/anomaly.rs`) et l'API (`web.rs`) l'utilisent, pas l'inverse.

pub mod baseline;
pub mod diff;
pub mod features;
pub mod iforest;
pub mod model;
pub mod storage;
pub mod trainer;
