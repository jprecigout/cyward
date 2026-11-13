//! Noms des machines : résolution DNS inverse (PTR) des adresses citées dans les alertes.
//!
//! Le dashboard affiche le nom à côté de l'adresse (« 192.168.1.20 · pc-salon.lan »). Il le
//! demande à la volée par `GET /api/names` (`web.rs`) : rien n'est résolu sur le chemin critique
//! de la détection, et les alertes elles-mêmes restent inchangées.
//!
//! - Logique pure, testable sans réseau : nom PTR d'une adresse, construction de la requête,
//!   lecture de la réponse (compression des noms comprise), lecture de `/etc/resolv.conf`.
//! - I/O en bordure : une requête UDP par adresse vers le serveur DNS, avec un délai maximal.
//! - Cache borné, absences de nom comprises : le dashboard redemande les mêmes adresses à
//!   chaque rechargement.
//!
//! Par défaut, seules les adresses internes (`detection.local_networks`) sont résolues : la
//! question PTR d'une adresse externe aboutit au serveur DNS de son propriétaire, ce qui
//! préviendrait un attaquant qui surveille sa zone que son adresse est examinée.

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicU16, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use parking_lot::Mutex;
use tokio::net::UdpSocket;

use crate::{alert::host_part, config::NamesConfig};

/// Nombre maximal d'adresses gardées en cache.
const MAX_ENTRIES: usize = 4096;
/// Nombre maximal d'adresses résolues par appel (une requête de l'API).
pub const MAX_BATCH: usize = 64;
/// Durée de conservation d'une absence de nom : plus courte que celle d'un nom trouvé, pour
/// qu'une machine qui vient de s'enregistrer auprès de la box apparaisse vite.
const NEGATIVE_TTL: Duration = Duration::from_secs(300);
/// Longueur maximale d'un nom DNS complet (RFC 1035), en octets.
const MAX_NAME_LEN: usize = 253;
/// Nombre maximal de pointeurs de compression suivis pour lire un nom.
const MAX_JUMPS: usize = 16;
/// Taille maximale d'une réponse DNS sur UDP sans EDNS, en octets.
const MAX_UDP: usize = 512;
/// Type d'enregistrement PTR.
const TYPE_PTR: u16 = 12;
/// Classe IN (Internet).
const CLASS_IN: u16 = 1;

/// Une entrée du cache : le nom (`None` = pas de nom) et sa date d'expiration.
struct Entry {
    name: Option<String>,
    expires: Instant,
}

/// Résolveur de noms avec cache, partagé par les requêtes du serveur web.
pub struct Resolver {
    cfg: NamesConfig,
    /// Réseaux internes : seules leurs adresses sont résolues, sauf si `names.external`.
    local: Vec<IpNet>,
    /// Serveur DNS interrogé (port 53) ; `None` = résolution désactivée.
    server: Option<SocketAddr>,
    cache: Mutex<HashMap<IpAddr, Entry>>,
    /// Plafond du cache : `MAX_ENTRIES`, réduit dans les tests.
    max_entries: usize,
    /// Identifiant de la prochaine requête DNS.
    next_id: AtomicU16,
}

impl Resolver {
    /// Prépare le résolveur. Sans `names.nameserver`, prend le premier serveur de
    /// `/etc/resolv.conf`. Si aucun serveur n'est utilisable, la résolution est désactivée
    /// avec un avertissement : les adresses s'affichent alors simplement sans nom.
    pub fn new(cfg: NamesConfig, local: Vec<IpNet>) -> Self {
        let server = if !cfg.enabled {
            None
        } else if cfg.nameserver.trim().is_empty() {
            let found = std::fs::read_to_string("/etc/resolv.conf").ok().and_then(|s| first_nameserver(&s));
            if found.is_none() {
                tracing::warn!("noms des machines désactivés : aucun serveur DNS dans /etc/resolv.conf (renseigner names.nameserver)");
            }
            found
        } else {
            let parsed = cfg.nameserver.trim().parse().ok();
            if parsed.is_none() {
                tracing::warn!("noms des machines désactivés : names.nameserver « {} » n'est pas une adresse IP", cfg.nameserver);
            }
            parsed
        };
        Self::with_server(cfg, local, server.map(|ip| SocketAddr::new(ip, 53)))
    }

    /// Construit le résolveur avec un serveur donné (port compris) : sert aux tests.
    fn with_server(cfg: NamesConfig, local: Vec<IpNet>, server: Option<SocketAddr>) -> Self {
        // Identifiant de départ imprévisible d'un démarrage à l'autre : avec le port source
        // aléatoire, il rend plus difficile d'injecter une fausse réponse depuis le réseau.
        let seed = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.subsec_nanos() as u16).unwrap_or(0);
        Self { cfg, local, server, cache: Mutex::new(HashMap::new()), max_entries: MAX_ENTRIES, next_id: AtomicU16::new(seed) }
    }

    /// Vrai si le nom de cette adresse peut être demandé (voir l'en-tête du module).
    fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.cfg.external || ip.is_loopback() || self.local.iter().any(|n| n.contains(ip))
    }

    /// Noms des valeurs `src`/`dst` données (« 10.0.0.1 », « 10.0.0.1:22 »…), indexés par la
    /// valeur telle que reçue. Sont absentes du résultat : les valeurs qui ne sont pas des
    /// adresses (domaine, compte), celles à ne pas résoudre, et celles sans nom.
    pub async fn names(&self, values: &[String]) -> HashMap<String, String> {
        let Some(server) = self.server else { return HashMap::new() };
        let wanted: Vec<(&String, IpAddr)> = values
            .iter()
            .take(MAX_BATCH)
            .filter_map(|v| host_part(v).parse().ok().map(|ip| (v, ip)))
            .filter(|(_, ip)| self.is_allowed(ip))
            .collect();

        // Adresses absentes du cache ou expirées, résolues en parallèle hors du verrou.
        let missing: HashSet<IpAddr> = {
            let cache = self.cache.lock();
            let now = Instant::now();
            wanted.iter().map(|(_, ip)| *ip).filter(|ip| !cache.get(ip).is_some_and(|e| e.expires > now)).collect()
        };
        let resolved = futures::future::join_all(missing.into_iter().map(|ip| async move { (ip, self.query(server, ip).await) })).await;

        let mut cache = self.cache.lock();
        let now = Instant::now();
        if cache.len() + resolved.len() > self.max_entries {
            // Mémoire bornée : on retire d'abord les entrées expirées, puis tout s'il le faut
            // (les noms seront simplement redemandés).
            cache.retain(|_, e| e.expires > now);
            if cache.len() + resolved.len() > self.max_entries {
                cache.clear();
            }
        }
        for (ip, name) in resolved {
            let ttl = if name.is_some() { Duration::from_secs(self.cfg.cache_secs) } else { NEGATIVE_TTL };
            cache.insert(ip, Entry { name, expires: now + ttl });
        }
        wanted.into_iter().filter_map(|(v, ip)| cache.get(&ip)?.name.clone().map(|n| (v.clone(), n))).collect()
    }

    /// Pose la question PTR au serveur. `None` si l'adresse n'a pas de nom, si le serveur ne
    /// répond pas à temps ou si la réponse est invalide : ces cas se valent pour l'affichage.
    async fn query(&self, server: SocketAddr, ip: IpAddr) -> Option<String> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        match self.exchange(server, &build_query(id, &ptr_name(ip))).await {
            Ok(resp) => parse_ptr(id, &resp),
            Err(e) => {
                tracing::debug!("nom de {ip} : {e:#}");
                None
            }
        }
    }

    /// Envoie une requête DNS en UDP et attend la réponse, au plus `names.timeout_ms`.
    async fn exchange(&self, server: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        let local: SocketAddr = if server.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
        let sock = UdpSocket::bind(local).await?;
        // `connect` filtre les datagrammes : seules les réponses du serveur interrogé sont lues.
        sock.connect(server).await?;
        sock.send(query).await?;
        let mut buf = vec![0u8; MAX_UDP];
        let n = tokio::time::timeout(Duration::from_millis(self.cfg.timeout_ms), sock.recv(&mut buf)).await.context("délai dépassé")??;
        buf.truncate(n);
        Ok(buf)
    }
}

/// Nom à interroger pour le PTR d'une adresse : « 4.3.2.1.in-addr.arpa » pour 1.2.3.4, et les
/// 32 chiffres hexadécimaux dans l'ordre inverse suivis de « ip6.arpa » en IPv6.
fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            // Chaque octet donne deux chiffres : celui de poids faible d'abord, puisque tout est inversé.
            let nibbles: Vec<String> = v6.octets().iter().rev().flat_map(|b| [format!("{:x}", b & 0xf), format!("{:x}", b >> 4)]).collect();
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

/// Requête DNS d'une question PTR : en-tête de 12 octets (identifiant, récursion demandée, une
/// question), puis le nom en segments préfixés par leur longueur, le type et la classe.
fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = Vec::with_capacity(12 + name.len() + 6);
    q.extend_from_slice(&id.to_be_bytes());
    // Drapeaux : seul RD (récursion souhaitée) ; puis QDCOUNT = 1, ANCOUNT = NSCOUNT = ARCOUNT = 0.
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&TYPE_PTR.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q
}

/// Nom contenu dans la réponse à la requête `id` : premier enregistrement PTR de la section
/// réponse. `None` si la réponse ne correspond pas à la requête, signale une erreur (nom
/// inexistant…), n'a pas de PTR, est malformée, ou si le nom n'est pas un nom de machine valide.
fn parse_ptr(id: u16, buf: &[u8]) -> Option<String> {
    let u16_at = |p: usize| buf.get(p..p + 2).map(|b| u16::from_be_bytes([b[0], b[1]]));
    if buf.len() < 12 || u16_at(0)? != id {
        return None;
    }
    // Bit QR (c'est une réponse) obligatoire, code de retour (4 bits bas) nul.
    if buf[2] & 0x80 == 0 || buf[3] & 0x0f != 0 {
        return None;
    }
    let (questions, answers) = (u16_at(4)?, u16_at(6)?);
    let mut pos = 12;
    for _ in 0..questions {
        // Nom, puis type et classe (4 octets).
        pos = read_name(buf, pos)?.1 + 4;
    }
    for _ in 0..answers {
        // Nom, type, classe, TTL (4 octets), longueur des données, données.
        let next = read_name(buf, pos)?.1;
        let (rtype, rdlen) = (u16_at(next)?, u16_at(next + 8)? as usize);
        let rdata = next + 10;
        if rtype == TYPE_PTR {
            let name = read_name(buf, rdata)?.0;
            return is_hostname(&name).then_some(name);
        }
        // Autre enregistrement (CNAME d'une délégation sans classe…) : on passe au suivant.
        pos = rdata + rdlen;
    }
    None
}

/// Lit un nom DNS à la position `pos` : suite de segments préfixés par leur longueur, terminée
/// par un octet nul ou par un pointeur de compression (2 octets commençant par 0b11) vers un nom
/// écrit plus haut dans le message. Renvoie le nom (segments joints par « . ») et la position
/// qui suit le nom. Les sauts sont limités à `MAX_JUMPS` : une réponse piégée qui boucle sur
/// elle-même est rejetée au lieu de bloquer.
fn read_name(buf: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    // Position qui suit le nom dans le message : juste après le premier pointeur s'il y en a un.
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            break;
        } else if len & 0xC0 == 0xC0 {
            jumps += 1;
            if jumps > MAX_JUMPS {
                return None;
            }
            end.get_or_insert(pos + 2);
            pos = ((len & 0x3F) << 8) | *buf.get(pos + 1)? as usize;
        } else if len & 0xC0 != 0 {
            // 0b01 et 0b10 : types de segment réservés.
            return None;
        } else {
            labels.push(String::from_utf8_lossy(buf.get(pos + 1..pos + 1 + len)?).into_owned());
            pos += 1 + len;
        }
    }
    let name = labels.join(".");
    (name.len() <= MAX_NAME_LEN).then_some((name, end.unwrap_or(pos + 1)))
}

/// Vrai pour un nom de machine plausible : segments de 1 à 63 caractères ASCII alphanumériques,
/// « - » ou « _ ». Le nom vient du réseau : tout le reste est refusé plutôt qu'affiché.
fn is_hostname(name: &str) -> bool {
    !name.is_empty()
        && name.split('.').all(|l| (1..=63).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

/// Premier serveur `nameserver` d'un fichier au format de `/etc/resolv.conf`. Les adresses
/// IPv6 avec zone (« fe80::1%eth0 ») sont ignorées : elles ne se convertissent pas en `IpAddr`.
fn first_nameserver(resolv_conf: &str) -> Option<IpAddr> {
    resolv_conf.lines().find_map(|l| l.trim().strip_prefix("nameserver")?.split_whitespace().next()?.parse().ok())
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    /// Configuration de test : activée, délai court.
    fn cfg(external: bool) -> NamesConfig {
        NamesConfig { enabled: true, external, nameserver: String::new(), timeout_ms: 500, cache_secs: 3600 }
    }

    /// Réseaux internes de test.
    fn local() -> Vec<IpNet> {
        vec!["192.168.0.0/16".parse().unwrap()]
    }

    /// Réponse DNS à `query` : un PTR vers `name`, ou « nom inexistant » si `name` est None.
    fn answer(query: &[u8], name: Option<&str>) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] = 0x81; // QR + RD
        r[3] = if name.is_some() { 0x80 } else { 0x83 }; // RA, code 0 ou 3 (NXDOMAIN)
        let Some(name) = name else { return r };
        r[7] = 1; // ANCOUNT = 1
        // Nom de la réponse : pointeur vers la question (position 12), comme le font les serveurs.
        r.extend_from_slice(&[0xC0, 12]);
        r.extend_from_slice(&TYPE_PTR.to_be_bytes());
        r.extend_from_slice(&CLASS_IN.to_be_bytes());
        r.extend_from_slice(&3600u32.to_be_bytes());
        let mut rdata = Vec::new();
        for l in name.split('.') {
            rdata.push(l.len() as u8);
            rdata.extend_from_slice(l.as_bytes());
        }
        rdata.push(0);
        r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        r.extend_from_slice(&rdata);
        r
    }

    /// Faux serveur DNS local : répond `name` à toute question et compte les requêtes reçues.
    async fn fake_server(name: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf).await {
                c.fetch_add(1, Ordering::SeqCst);
                sock.send_to(&answer(&buf[..n], Some(name)), from).await.unwrap();
            }
        });
        (addr, count)
    }

    // Noms PTR : octets inversés en IPv4, chiffres hexadécimaux inversés en IPv6.
    #[test]
    fn ptr_names() {
        assert_eq!(ptr_name("192.168.1.20".parse().unwrap()), "20.1.168.192.in-addr.arpa");
        let v6 = ptr_name("2001:db8::567:89ab".parse().unwrap());
        assert_eq!(v6, "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
    }

    // Une réponse PTR bien formée, avec compression du nom, donne le nom de la machine.
    #[test]
    fn parses_ptr_answer() {
        let q = build_query(0x1234, "20.1.168.192.in-addr.arpa");
        assert_eq!(parse_ptr(0x1234, &answer(&q, Some("pc-salon.lan"))), Some("pc-salon.lan".into()));
    }

    // Pas de nom : identifiant différent, nom inexistant, requête renvoyée telle quelle, message tronqué.
    #[test]
    fn rejects_unrelated_or_empty_answers() {
        let q = build_query(7, "20.1.168.192.in-addr.arpa");
        assert_eq!(parse_ptr(8, &answer(&q, Some("pc-salon.lan"))), None);
        assert_eq!(parse_ptr(7, &answer(&q, None)), None);
        assert_eq!(parse_ptr(7, &q), None);
        let full = answer(&q, Some("pc-salon.lan"));
        assert_eq!(parse_ptr(7, &full[..full.len() - 3]), None);
    }

    // Une réponse piégée (pointeur qui boucle, nom avec des caractères de contrôle) est rejetée.
    #[test]
    fn rejects_malicious_answers() {
        let q = build_query(7, "20.1.168.192.in-addr.arpa");
        let mut looped = answer(&q, Some("x"));
        let rdata = looped.len() - 3;
        looped[rdata] = 0xC0;
        looped[rdata + 1] = rdata as u8; // pointeur vers lui-même
        assert_eq!(parse_ptr(7, &looped), None);
        assert_eq!(parse_ptr(7, &answer(&q, Some("evil<script>.lan"))), None);
    }

    // Lecture de /etc/resolv.conf : commentaires ignorés, premier serveur retenu.
    #[test]
    fn reads_first_nameserver() {
        let conf = "# généré par systemd-resolved\nsearch lan\nnameserver 127.0.0.53\nnameserver 1.1.1.1\n";
        assert_eq!(first_nameserver(conf), Some("127.0.0.53".parse().unwrap()));
        assert_eq!(first_nameserver("search lan\n"), None);
    }

    // Une adresse interne est résolue (port retiré), puis servie par le cache sans nouvelle requête ;
    // une adresse externe, un domaine et un compte ne sont pas résolus.
    #[tokio::test]
    async fn resolves_local_addresses_with_cache() {
        let (server, count) = fake_server("pc-salon.lan").await;
        let r = Resolver::with_server(cfg(false), local(), Some(server));
        let values: Vec<String> = ["192.168.1.20:443", "203.0.113.5", "tunnel-exfil.net", "admin"].map(String::from).into();
        let names = r.names(&values).await;
        assert_eq!(names.len(), 1);
        assert_eq!(names["192.168.1.20:443"], "pc-salon.lan");
        assert_eq!(count.load(Ordering::SeqCst), 1);
        // Même adresse sous une autre forme : une seule entrée de cache, pas de nouvelle requête.
        assert_eq!(r.names(&["192.168.1.20".to_string()]).await["192.168.1.20"], "pc-salon.lan");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    // Avec `names.external`, les adresses externes sont résolues aussi.
    #[tokio::test]
    async fn resolves_external_addresses_when_allowed() {
        let (server, _) = fake_server("one.one.one.one").await;
        let r = Resolver::with_server(cfg(true), local(), Some(server));
        assert_eq!(r.names(&["1.1.1.1".to_string()]).await["1.1.1.1"], "one.one.one.one");
    }

    // Serveur muet : pas de nom, au bout du délai, et l'absence est mise en cache.
    #[tokio::test]
    async fn silent_server_gives_no_name() {
        let mute = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let r = Resolver::with_server(NamesConfig { timeout_ms: 50, ..cfg(false) }, local(), Some(mute.local_addr().unwrap()));
        assert!(r.names(&["192.168.1.20".to_string()]).await.is_empty());
        assert!(r.cache.lock()[&"192.168.1.20".parse::<IpAddr>().unwrap()].name.is_none());
    }

    // Le cache ne dépasse jamais son plafond.
    #[tokio::test]
    async fn cache_is_bounded() {
        let (server, _) = fake_server("pc.lan").await;
        let mut r = Resolver::with_server(cfg(false), local(), Some(server));
        r.max_entries = 4;
        for i in 0..10 {
            r.names(&[format!("192.168.1.{i}")]).await;
            assert!(r.cache.lock().len() <= 4);
        }
    }

    // Résolution désactivée : aucun nom, aucune requête.
    #[tokio::test]
    async fn disabled_resolver_returns_nothing() {
        let r = Resolver::new(NamesConfig { enabled: false, ..cfg(false) }, local());
        assert!(r.names(&["192.168.1.20".to_string()]).await.is_empty());
    }
}
