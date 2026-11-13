//! Bannière affichée au démarrage de la surveillance : le bouclier et sa pulsation (reprise
//! du logo `assets/logo.svg`), le nom en grandes lettres, la version, puis un résumé de la
//! configuration effective (dashboard, capture, logs, modèle).
//!
//! Les couleurs utilisent la palette 256 couleurs, reconnue par presque tous les terminaux.
//! Elles sont désactivées quand la sortie n'est pas un terminal (journal systemd, `docker logs`,
//! redirection vers un fichier) ou quand la variable `NO_COLOR` est définie (convention no-color.org).

use std::io::IsTerminal;

/// Bouclier : 8 lignes de 15 colonnes. Les lignes 1 à 3 contiennent la pulsation, qui reprend
/// le tracé du logo (ligne plate, pic, creux, retour à la ligne de base).
const SHIELD: [&str; 8] = [
    "╭─────────────╮",
    "│      ╱╲     │",
    "│ ────╱  ╲  ──│",
    "│         ╲╱  │",
    " ╲           ╱ ",
    "   ╲       ╱   ",
    "     ╲   ╱     ",
    "       V       ",
];

/// « CYWARD » dans la police figlet « ANSI Shadow » : une entrée par lettre, 6 lignes chacune.
/// Les lettres sont gardées séparées pour pouvoir colorer chacune différemment (dégradé).
const LETTERS: [[&str; 6]; 6] = [
    [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
    ["██╗   ██╗", "╚██╗ ██╔╝", " ╚████╔╝ ", "  ╚██╔╝  ", "   ██║   ", "   ╚═╝   "],
    ["██╗    ██╗", "██║    ██║", "██║ █╗ ██║", "██║███╗██║", "╚███╔███╔╝", " ╚══╝╚══╝ "],
    [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
    ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
];

// Codes de la palette 256 couleurs, choisis pour suivre le dégradé bleu → vert du logo.
/// Contour du bouclier (bleu, proche de #58a6ff).
const BLUE: u8 = 75;
/// Pulsation (vert, proche de #3fb950).
const GREEN: u8 = 77;
/// Texte secondaire (gris).
const GREY: u8 = 245;
/// Une couleur par lettre de « CYWARD », du bleu au vert.
const GRADIENT: [u8; 6] = [75, 81, 80, 79, 78, 77];

/// Vrai si la bannière doit être colorée : sortie standard reliée à un terminal, et
/// `NO_COLOR` absent.
pub fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Construit la bannière complète. `info` est une liste de paires (libellé, valeur)
/// affichées sous le logo ; `color` active les séquences ANSI.
pub fn render(info: &[(&str, String)], color: bool) -> String {
    // Entoure un texte d'une couleur, ou le renvoie tel quel si les couleurs sont désactivées.
    let paint = |s: &str, code: u8| if color { format!("\x1b[38;5;{code}m{s}\x1b[0m") } else { s.to_string() };

    // Texte placé à droite du bouclier, ligne par ligne : le nom sur les 6 premières lignes,
    // puis la description et la version sur les 2 dernières.
    let mut right: Vec<String> =
        (0..6).map(|row| LETTERS.iter().zip(GRADIENT).map(|(letter, code)| paint(letter[row], code)).collect()).collect();
    right.push(paint("Détection d'intrusions · triage par IA locale", GREY));
    right.push(paint(&format!("v{}", env!("CARGO_PKG_VERSION")), GREY));

    let mut out = String::from("\n");
    for (row, (shield, text)) in SHIELD.iter().zip(&right).enumerate() {
        out.push_str("  ");
        out.push_str(&paint_shield_row(row, shield, color));
        out.push_str("   ");
        out.push_str(text);
        out.push('\n');
    }

    // Résumé de la configuration, libellés alignés.
    if !info.is_empty() {
        out.push('\n');
        for (label, value) in info {
            out.push_str(&format!("  {}  {value}\n", paint(&format!("{label:<10}"), GREY)));
        }
    }
    out.push('\n');
    out
}

/// Colore une ligne du bouclier : la pulsation en vert (intérieur des lignes 1 à 3), tout le
/// reste en bleu. Les espaces ne sont pas colorés, pour éviter des séquences inutiles.
fn paint_shield_row(row: usize, line: &str, color: bool) -> String {
    if !color {
        return line.to_string();
    }
    let width = line.chars().count();
    line.chars()
        .enumerate()
        .map(|(col, ch)| {
            if ch == ' ' {
                return ch.to_string();
            }
            // Intérieur du bouclier sur les lignes de la pulsation : ni la bordure gauche, ni la droite.
            let pulse = (1..=3).contains(&row) && col > 0 && col < width - 1;
            format!("\x1b[38;5;{}m{ch}\x1b[0m", if pulse { GREEN } else { BLUE })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Retire les séquences ANSI (ESC [ … m) pour comparer le texte visible.
    fn strip_ansi(s: &str) -> String {
        let mut out = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                for c in chars.by_ref() {
                    if c == 'm' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    // Toutes les lignes du bouclier ont la même largeur, sinon le texte à droite serait désaligné.
    #[test]
    fn shield_rows_have_equal_width() {
        assert!(SHIELD.iter().all(|l| l.chars().count() == 15));
    }

    // Chaque lettre a 6 lignes de même largeur, sinon les lettres suivantes seraient décalées.
    #[test]
    fn letters_rows_have_equal_width() {
        for letter in LETTERS {
            let w = letter[0].chars().count();
            assert!(letter.iter().all(|l| l.chars().count() == w), "{letter:?}");
        }
    }

    // Sans couleur : aucune séquence ANSI, la version et le résumé sont présents, et rien ne
    // dépasse 80 colonnes (largeur d'un terminal par défaut).
    #[test]
    fn plain_banner_fits_80_columns() {
        let b = render(&[("Dashboard", "http://127.0.0.1:8080".into())], false);
        assert!(!b.contains('\x1b'));
        assert!(b.contains(concat!("v", env!("CARGO_PKG_VERSION"))));
        assert!(b.contains("Dashboard"));
        assert!(b.contains("http://127.0.0.1:8080"));
        assert!(b.lines().all(|l| l.chars().count() <= 80), "{b}");
    }

    // Avec couleur : des séquences ANSI sont présentes, mais le texte visible est identique
    // à la version sans couleur.
    #[test]
    fn colored_banner_has_same_visible_text() {
        let info = [("Modèle IA", "foundation-sec".to_string())];
        let colored = render(&info, true);
        assert!(colored.contains("\x1b[38;5;"));
        assert_eq!(strip_ansi(&colored), render(&info, false));
    }

    // Sans résumé de configuration, la bannière ne contient que le logo et le nom.
    #[test]
    fn empty_info_has_no_summary_block() {
        assert_eq!(render(&[], false).lines().count(), 10);
    }
}
