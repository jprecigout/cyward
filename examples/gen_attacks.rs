//! Génère un pcap contenant du trafic normal et plusieurs attaques simulées, pour tester
//! les détecteurs sans toucher à un vrai réseau :
//!
//!   cargo run --example gen_attacks -- attaques.pcap
//!   cargo run -- replay attaques.pcap
//!
//! Le rejeu doit produire 7 alertes : balise C2, force brute SSH, scan de ports, balayage
//! du port 445, tunnel DNS, volume sortant anormal et usurpation ARP de la passerelle. Avec
//! la configuration d'exemple, qui charge la liste de menaces `examples/menaces.txt`, une
//! 8e alerte signale la connexion vers une IP listée :
//!
//!   cargo run -- -c examples/rejeu.toml replay attaques.pcap
//!
//! Le trafic du portable et les annonces ARP ordinaires ne doivent en déclencher aucune
//! (contrôle des faux positifs).

use std::{fs::File, time::Duration};

use etherparse::{ArpEthIpv4Packet, ArpOperation, PacketBuilder};
use pcap_file::pcap::{PcapPacket, PcapWriter};

/// Les scénarios sont générés l'un après l'autre puis triés par date, comme dans une vraie capture.
struct Gen {
    /// Paquets en attente d'écriture : (secondes depuis le début du scénario, trame Ethernet).
    packets: Vec<(f64, Vec<u8>)>,
}

impl Gen {
    fn write(&mut self, ts: f64, frame: Vec<u8>) {
        self.packets.push((ts, frame));
    }

    /// Trie les paquets par date et les écrit dans le fichier, décalés de `t0` (epoch).
    /// Le tri est indispensable : les détecteurs supposent un temps qui avance.
    fn save(mut self, path: &str, t0: f64) {
        self.packets.sort_by(|a, b| a.0.total_cmp(&b.0));
        let mut writer = PcapWriter::new(File::create(path).unwrap()).unwrap();
        for (ts, frame) in &self.packets {
            let ts = Duration::from_secs_f64(t0 + ts);
            writer.write_packet(&PcapPacket::new(ts, frame.len() as u32, frame)).unwrap();
        }
    }

    /// Ouverture de connexion TCP (SYN seul) vers `dst:dport`.
    fn syn(&mut self, ts: f64, src: [u8; 4], dst: [u8; 4], dport: u16) {
        let mut buf = Vec::new();
        // Adresses MAC fictives : seules les couches IP et TCP intéressent les détecteurs.
        PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
            .ipv4(src, dst, 64)
            // Port source variable, comme le choisirait un vrai client.
            .tcp(40000 + (ts as u16 % 20000), dport, 1, 64240)
            .syn()
            .write(&mut buf, &[])
            .unwrap();
        self.write(ts, buf);
    }

    /// Segment TCP de données (ACK) de `len` octets vers le port 443 : du trafic établi,
    /// qui compte pour le volume mais pas comme nouvelle connexion.
    fn tcp_data(&mut self, ts: f64, src: [u8; 4], dst: [u8; 4], len: usize) {
        let mut buf = Vec::new();
        PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
            .ipv4(src, dst, 64)
            .tcp(51000, 443, 1000, 64240)
            .ack(1)
            .write(&mut buf, &vec![0u8; len])
            .unwrap();
        self.write(ts, buf);
    }

    /// Requête DNS de type A pour `name`, envoyée au résolveur 192.168.1.1.
    fn dns(&mut self, ts: f64, src: [u8; 4], name: &str) {
        // En-tête : identifiant, drapeaux « requête récursive », 1 question.
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        // Nom encodé en segments « longueur + texte ».
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        // Fin du nom, type A, classe IN.
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        let mut buf = Vec::new();
        PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
            .ipv4(src, [192, 168, 1, 1], 64)
            .udp(53000, 53)
            .write(&mut buf, &q)
            .unwrap();
        self.write(ts, buf);
    }

    /// Réponse ARP non sollicitée (ARP gratuit) diffusée par `mac` : « `ip` est à moi ».
    fn arp_reply(&mut self, ts: f64, ip: [u8; 4], mac: [u8; 6]) {
        let arp =
            ArpEthIpv4Packet { operation: ArpOperation::REPLY, sender_mac: mac, sender_ipv4: ip, target_mac: [0xff; 6], target_ipv4: ip };
        let mut buf = Vec::new();
        PacketBuilder::ethernet2(mac, [0xff; 6]).arp(arp.to_arp_packet()).write(&mut buf).unwrap();
        self.write(ts, buf);
    }
}

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| "attaques.pcap".into());
    let mut g = Gen { packets: Vec::new() };

    // Acteurs du scénario. Les adresses externes sont dans des plages réservées à la
    // documentation (RFC 5737), qui n'appartiennent à personne.
    let workstation = [192, 168, 1, 20];
    let laptop = [192, 168, 1, 35];
    let server = [192, 168, 1, 10];
    let attacker = [203, 0, 113, 77];
    let c2 = [198, 51, 100, 66];
    let gateway = [192, 168, 1, 1];
    let (gateway_mac, laptop_mac, workstation_mac) = ([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 0x35], [2, 0, 0, 0, 0, 0x20]);
    // Serveur de commande recensé dans examples/menaces.txt (plage de documentation RFC 5737).
    let listed_c2 = [192, 0, 2, 200];

    // Trafic de fond normal pendant 40 minutes : navigation et DNS ordinaires.
    for s in (0..2400).step_by(3) {
        let t = s as f64;
        g.tcp_data(t, laptop, [93, 184, 216, 34], 1200);
        if s % 30 == 0 {
            g.dns(t, laptop, ["www.wikipedia.org", "github.com", "fonts.googleapis.com"][s as usize / 30 % 3]);
        }
    }

    // Annonces ARP ordinaires de la passerelle et du portable, toutes les minutes.
    for s in (0..2400).step_by(60) {
        g.arp_reply(s as f64, gateway, gateway_mac);
        g.arp_reply(s as f64 + 0.5, laptop, laptop_mac);
    }

    // Poste compromis : balise C2 toutes les 60 s (± 1 s).
    for i in 0..20 {
        g.syn(100.0 + i as f64 * 60.0 + (i % 3) as f64 * 0.5, workstation, c2, 8443);
    }

    // Attaquant externe : force brute SSH sur le serveur.
    for i in 0..40 {
        g.syn(600.0 + i as f64 * 1.2, attacker, server, 22);
    }

    // Le poste compromis scanne le réseau interne (mouvement latéral).
    for port in 1..=200u16 {
        g.syn(900.0 + port as f64 * 0.05, workstation, server, port);
    }
    for host in 1..=40u8 {
        g.syn(960.0 + host as f64 * 0.1, workstation, [192, 168, 1, host], 445);
    }

    // Puis exfiltre par tunnel DNS…
    // (sous-domaines de 16 caractères hexadécimaux pseudo-aléatoires, tous différents)
    for i in 0..300 {
        g.dns(1200.0 + i as f64 * 0.5, workstation, &format!("{:016x}.d.tunnel-exfil.net", (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15)));
    }

    // …et par un gros transfert HTTPS sortant après 30 minutes de trafic modeste.
    // Les 30 minutes servent à établir la normale du poste (~12 Ko/min) ; le pic fait ~85 Mo en 1 minute.
    for s in (0..1800).step_by(10) {
        g.tcp_data(s as f64, workstation, c2, 2000);
    }
    for i in 0..60_000 {
        g.tcp_data(1800.0 + i as f64 * 0.001, workstation, c2, 1400);
    }

    // Il contacte aussi un serveur de commande connu des listes de menaces…
    for i in 0..3 {
        g.syn(1400.0 + i as f64 * 5.0, workstation, listed_c2, 443);
    }

    // …et se fait passer pour la passerelle (empoisonnement ARP) pour intercepter le trafic du réseau.
    for i in 0..30 {
        g.arp_reply(1500.0 + i as f64 * 2.0, gateway, workstation_mac);
    }

    let n = g.packets.len();
    g.save(&path, 1_794_391_200.0); // 11/11/2026 10:00 UTC
    println!("{n} paquets écrits dans {path}");
}
