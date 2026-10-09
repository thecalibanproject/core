//! Deterministic guards for what a similarity threshold cannot separate.
//!
//! Embeddings place "Convert 100 USD to EUR" and "Convert 100 EUR to USD" at cosine 0.988,
//! "into Spanish" and "into Italian" at 0.952, and "explain briefly" and "explain in detail" at
//! 0.989 (Qwen3-Embedding-0.6B, `bench/RESULTS-aws-2026-10.md`): above any usable threshold. So
//! before two prompts may share an answer, the facts below must be equal. They are part of the
//! semantic key's partition ([`super::SemanticKey`]), so prompts that differ in them are never
//! compared at all:
//!
//! - **Slots, in order of appearance**: tokens with a digit (numbers, dates, versions, IDs such as
//!   `Q3` or `12345`); currency codes and names (`USD`, `eur`, `euros`) and currency symbols;
//!   units (`km`, `miles`, `°F`, `GB`, `hours`) when the prompt contains a number; language names
//!   (`Spanish`, `español`, `espagnol` are one slot); acronyms and codes in capitals (`CAP`,
//!   `SQL`); and capitalised words that do not start a sentence (names of people, places,
//!   products, months). Order matters, so a swapped direction ("USD to EUR" vs "EUR to USD",
//!   "Paris to London" vs "London to Paris") never matches.
//! - **Modifier classes**, as a set: negation (`not`, `never`, `without`, `n't`, and their common
//!   equivalents in German, French, Spanish, Italian, Portuguese and Dutch), length and depth
//!   (`briefly` vs `in detail`), and opposite pairs such as enable/disable, increase/decrease,
//!   maximum/minimum, first/last, before/after, add/remove, above/below, buy/sell,
//!   import/export, encrypt/decrypt, ascending/descending, start/stop, today/tomorrow.
//!
//! Every rule can only turn a would-be hit into a miss, never the reverse: a word list that misses
//! a language or a synonym just leaves that pair to the threshold, as before. Prompts in scripts
//! without letter case (Chinese, Japanese, Arabic, ...) still get number, code and symbol slots.
//! Paraphrases that keep the same facts in the same order still share a partition ("into Spanish"
//! vs "how do you say ... in Spanish"); ones that reorder them become misses. One pass over the
//! prompt, a few allocations: microseconds for a typical prompt.

/// What two prompts must share before one's answer may serve the other.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Signature {
    /// Lower-cased slots in order of appearance (language names as `lang:<code>`).
    pub slots: Vec<String>,
    /// Bit set of the modifier classes present (see [`Modifier`]).
    pub modifiers: u64,
}

impl Signature {
    /// The modifier classes present, for diagnostics and tests.
    pub fn modifier_names(&self) -> Vec<&'static str> {
        Modifier::ALL.iter().filter(|m| self.modifiers & m.bit() != 0).map(|m| m.name()).collect()
    }
}

/// Modifier classes. Opposites are distinct classes, so a prompt with one never matches a prompt
/// with the other (or with neither).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    Negation,
    Brief,
    Detailed,
    Enable,
    Disable,
    Increase,
    Decrease,
    Most,
    Least,
    First,
    Last,
    Before,
    After,
    Add,
    Remove,
    Above,
    Below,
    Buy,
    Sell,
    Import,
    Export,
    Encode,
    Decode,
    Ascending,
    Descending,
    Start,
    Stop,
    Login,
    Logout,
    Today,
    Tomorrow,
    Yesterday,
    Positive,
    Negative,
    Formal,
    Informal,
    Simple,
    Technical,
    Only,
    Against,
    Accept,
    Reject,
    Cheap,
    Expensive,
    Fast,
    Slow,
    North,
    South,
    East,
    West,
    Left,
    Right,
}

impl Modifier {
    pub const ALL: [Modifier; 52] = [
        Self::Negation,
        Self::Brief,
        Self::Detailed,
        Self::Enable,
        Self::Disable,
        Self::Increase,
        Self::Decrease,
        Self::Most,
        Self::Least,
        Self::First,
        Self::Last,
        Self::Before,
        Self::After,
        Self::Add,
        Self::Remove,
        Self::Above,
        Self::Below,
        Self::Buy,
        Self::Sell,
        Self::Import,
        Self::Export,
        Self::Encode,
        Self::Decode,
        Self::Ascending,
        Self::Descending,
        Self::Start,
        Self::Stop,
        Self::Login,
        Self::Logout,
        Self::Today,
        Self::Tomorrow,
        Self::Yesterday,
        Self::Positive,
        Self::Negative,
        Self::Formal,
        Self::Informal,
        Self::Simple,
        Self::Technical,
        Self::Only,
        Self::Against,
        Self::Accept,
        Self::Reject,
        Self::Cheap,
        Self::Expensive,
        Self::Fast,
        Self::Slow,
        Self::North,
        Self::South,
        Self::East,
        Self::West,
        Self::Left,
        Self::Right,
    ];

    pub fn bit(self) -> u64 {
        1 << (self as u32)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Negation => "negation",
            Self::Brief => "brief",
            Self::Detailed => "detailed",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Increase => "increase",
            Self::Decrease => "decrease",
            Self::Most => "most",
            Self::Least => "least",
            Self::First => "first",
            Self::Last => "last",
            Self::Before => "before",
            Self::After => "after",
            Self::Add => "add",
            Self::Remove => "remove",
            Self::Above => "above",
            Self::Below => "below",
            Self::Buy => "buy",
            Self::Sell => "sell",
            Self::Import => "import",
            Self::Export => "export",
            Self::Encode => "encode",
            Self::Decode => "decode",
            Self::Ascending => "ascending",
            Self::Descending => "descending",
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Login => "login",
            Self::Logout => "logout",
            Self::Today => "today",
            Self::Tomorrow => "tomorrow",
            Self::Yesterday => "yesterday",
            Self::Positive => "positive",
            Self::Negative => "negative",
            Self::Formal => "formal",
            Self::Informal => "informal",
            Self::Simple => "simple",
            Self::Technical => "technical",
            Self::Only => "only",
            Self::Against => "against",
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Cheap => "cheap",
            Self::Expensive => "expensive",
            Self::Fast => "fast",
            Self::Slow => "slow",
            Self::North => "north",
            Self::South => "south",
            Self::East => "east",
            Self::West => "west",
            Self::Left => "left",
            Self::Right => "right",
        }
    }
}

/// Separators after which the next word starts a sentence (or a quote, list item or heading),
/// where capitalisation says nothing about the word.
fn starts_sentence(c: char) -> bool {
    matches!(
        c,
        '.' | '!'
            | '?'
            | ':'
            | ';'
            | '\n'
            | '\r'
            | '"'
            | '\''
            | '`'
            | '“'
            | '”'
            | '„'
            | '‘'
            | '’'
            | '«'
            | '»'
            | '‹'
            | '›'
            | '('
            | '['
            | '{'
            | '¿'
            | '¡'
            | '*'
            | '#'
            | '•'
            | '。'
            | '！'
            | '？'
    )
}

/// Symbols that are slots on their own.
fn symbol_slot(c: char) -> bool {
    matches!(c, '$' | '€' | '£' | '¥' | '₹' | '₽' | '₩' | '₺' | '₪' | '฿' | '₿' | '¢' | '%' | '°')
}

struct Token<'a> {
    text: &'a str,
    /// First word of a sentence, quote or list item.
    initial: bool,
}

/// Words (letters and digits, with `.` `,` `'` `’` inside), and slot symbols as one-char tokens.
fn tokens(text: &str) -> Vec<Token<'_>> {
    let mut out = Vec::new();
    let mut initial = true;
    let mut start: Option<usize> = None;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let joiner = matches!(c, '.' | ',' | '\'' | '’');
        let inner = joiner
            && start.is_some()
            && chars.peek().is_some_and(|&(_, n)| n.is_alphanumeric())
            && text[..i].chars().next_back().is_some_and(char::is_alphanumeric);
        if c.is_alphanumeric() || inner {
            if start.is_none() {
                start = Some(i);
            }
            continue;
        }
        if let Some(s) = start.take() {
            out.push(Token { text: &text[s..i], initial });
            initial = false;
        }
        if symbol_slot(c) {
            out.push(Token { text: &text[i..i + c.len_utf8()], initial: false });
        }
        if starts_sentence(c) {
            initial = true;
        }
    }
    if let Some(s) = start {
        out.push(Token { text: &text[s..], initial });
    }
    out
}

/// Computes the [`Signature`] of a prompt.
pub fn signature(text: &str) -> Signature {
    let toks = tokens(text);
    let lower: Vec<String> = toks.iter().map(|t| t.text.to_lowercase()).collect();
    let has_number = toks.iter().any(|t| t.text.chars().any(char::is_numeric));
    let mut sig = Signature::default();
    for (i, (t, l)) in toks.iter().zip(&lower).enumerate() {
        let prev = i.checked_sub(1).map(|j| lower[j].as_str());
        if let Some(m) = modifier(l, prev) {
            sig.modifiers |= m.bit();
            continue;
        }
        if t.text.chars().any(char::is_numeric) || t.text.chars().all(symbol_slot) {
            sig.slots.push(l.clone());
        } else if let Some(code) = language(l) {
            sig.slots.push(format!("lang:{code}"));
        } else if let Some(code) = currency(t.text, l) {
            sig.slots.push(code);
        } else if let Some(unit) = unit(l).filter(|_| has_number) {
            sig.slots.push(unit.to_owned());
        } else if is_code(t.text) || (is_capitalised(t.text) && !t.initial && !is_pronoun_i(l)) {
            sig.slots.push(l.clone());
        }
    }
    sig
}

/// Two or more letters, all upper case (acronyms and codes: `CAP`, `SQL`, `GDPR`).
fn is_code(t: &str) -> bool {
    let mut letters = 0;
    for c in t.chars() {
        if c.is_alphabetic() {
            if !c.is_uppercase() {
                return false;
            }
            letters += 1;
        }
    }
    letters >= 2
}

fn is_capitalised(t: &str) -> bool {
    t.chars().next().is_some_and(char::is_uppercase)
}

/// English "I" and its contractions: capitalised everywhere, never a name.
fn is_pronoun_i(l: &str) -> bool {
    matches!(l, "i" | "i'm" | "i’m" | "i've" | "i’ve" | "i'll" | "i’ll" | "i'd" | "i’d")
}

/// The modifier class of a lower-cased word, given the word before it (for "turn on", "log out").
fn modifier(w: &str, prev: Option<&str>) -> Option<Modifier> {
    use Modifier::*;
    if let Some(p) = prev {
        match (p, w) {
            ("turn" | "switch", "on") => return Some(Enable),
            ("turn" | "switch", "off") => return Some(Disable),
            ("log" | "sign", "in" | "on") => return Some(Login),
            ("log" | "sign", "out" | "off") => return Some(Logout),
            _ => {}
        }
    }
    if w.ends_with("n't") || w.ends_with("n’t") {
        return Some(Negation);
    }
    // Stems first, negated forms before their positive counterparts.
    const STEMS: &[(&str, Modifier)] = &[
        ("deactivat", Disable),
        ("activat", Enable),
        ("disabl", Disable),
        ("enabl", Enable),
        ("disallow", Disable),
        ("allow", Enable),
        ("unblock", Enable),
        ("unlock", Enable),
        ("increas", Increase),
        ("decreas", Decrease),
        ("reduc", Decrease),
        ("maximi", Most),
        ("minimi", Least),
        ("decrypt", Decode),
        ("encrypt", Encode),
        ("decompress", Decode),
        ("compress", Encode),
        ("decod", Decode),
        ("encod", Encode),
        ("uninstall", Remove),
        ("ascend", Ascending),
        ("descend", Descending),
        ("detail", Detailed),
        ("thorough", Detailed),
        ("comprehensive", Detailed),
        ("exhaustiv", Detailed),
        ("ausführlich", Detailed),
        ("detaill", Detailed),
        ("détail", Detailed),
        ("detall", Detailed),
        ("dettagli", Detailed),
        ("detalh", Detailed),
        ("concise", Brief),
        ("succinct", Brief),
        ("brief", Brief),
        ("brevemente", Brief),
    ];
    for (stem, m) in STEMS {
        if w.starts_with(stem) {
            return Some(*m);
        }
    }
    Some(match w {
        "not" | "no" | "never" | "without" | "none" | "nothing" | "neither" | "nor" | "cannot" | "nicht" | "kein"
        | "keine" | "keinen" | "keiner" | "keinem" | "ohne" | "nie" | "niemals" | "ne" | "pas" | "sans" | "jamais"
        | "aucun" | "aucune" | "non" | "sin" | "nunca" | "ningún" | "ninguna" | "ninguno" | "senza" | "mai"
        | "nessun" | "nessuno" | "nessuna" | "sem" | "nenhum" | "nenhuma" | "não" | "niet" | "geen" | "zonder"
        | "nooit" => Negation,
        "short" | "shorter" | "shortly" | "quick" | "quickly" | "breve" | "corto" | "corta" | "court" | "courte"
        | "bref" | "brève" | "kurz" | "kurze" | "kurzer" | "kurzen" | "knapp" | "tldr" => Brief,
        "depth" | "elaborate" | "extensive" | "extensively" | "lengthy" => Detailed,
        "unhide" | "unmute" | "aktivieren" | "activer" | "activar" | "attivare" | "ativar" | "habilitar" => Enable,
        "block" | "blocks" | "blocked" | "blocking" | "lock" | "hide" | "mute" | "prevent" | "deaktivieren"
        | "désactiver" | "desactivar" | "disattivare" | "desativar" | "desabilitar" => Disable,
        "raise" | "raising" | "more" | "higher" | "grow" | "bigger" | "larger" | "boost" | "upgrade" | "rise"
        | "erhöhen" | "augmenter" | "aumentar" | "aumentare" => Increase,
        "lower" | "less" | "fewer" | "smaller" | "shrink" | "cut" | "downgrade" | "decline" | "verringern"
        | "réduire" | "diminuer" | "disminuir" | "ridurre" | "diminuire" | "diminuir" => Decrease,
        "max" | "maximum" | "highest" | "largest" | "biggest" | "most" | "best" | "top" | "greatest" => Most,
        "minimum" | "lowest" | "smallest" | "least" | "worst" | "fewest" | "bottom" => Least,
        "first" | "earliest" | "oldest" | "initial" => First,
        "last" | "latest" | "newest" | "recent" | "final" => Last,
        "before" | "prior" | "earlier" | "previous" | "vor" | "avant" | "antes" | "prima" => Before,
        "after" | "later" | "following" | "next" | "nach" | "après" | "después" | "dopo" | "depois" => After,
        "add" | "adding" | "create" | "creating" | "insert" | "install" | "include" | "including" | "append" => Add,
        "remove" | "removing" | "delete" | "deleting" | "drop" | "exclude" | "excluding" | "except" | "erase"
        | "purge" | "löschen" | "supprimer" | "eliminar" | "eliminare" | "excluir" => Remove,
        "above" | "over" | "exceeding" | "exceeds" | "greater" | "beyond" | "über" | "dessus" | "encima" | "sopra" => {
            Above
        }
        "below" | "under" | "beneath" | "unter" | "dessous" | "debajo" | "sotto" | "abaixo" => Below,
        "buy" | "buying" | "purchase" | "purchasing" | "kaufen" | "acheter" | "comprar" | "comprare" => Buy,
        "sell" | "selling" | "sale" | "verkaufen" | "vendre" | "vender" | "vendere" => Sell,
        "import" | "importing" | "upload" | "uploading" => Import,
        "export" | "exporting" | "download" | "downloading" => Export,
        "zip" => Encode,
        "unzip" => Decode,
        "start" | "starting" | "begin" | "launch" | "open" | "opening" | "resume" => Start,
        "stop" | "stopping" | "end" | "halt" | "terminate" | "close" | "closing" | "pause" | "kill" => Stop,
        "login" | "signin" => Login,
        "logout" | "signout" => Logout,
        "today" | "tonight" | "heute" | "aujourd'hui" | "aujourd’hui" | "hoy" | "oggi" | "hoje" => Today,
        "tomorrow" | "morgen" | "demain" | "mañana" | "domani" | "amanhã" => Tomorrow,
        "yesterday" | "gestern" | "hier" | "ayer" | "ieri" | "ontem" => Yesterday,
        "positive" | "positively" | "favorable" | "favourable" | "optimistic" => Positive,
        "negative" | "negatively" | "unfavorable" | "unfavourable" | "pessimistic" | "critical" => Negative,
        "formal" | "formally" | "professional" | "professionally" => Formal,
        "informal" | "informally" | "casual" | "casually" | "friendly" => Informal,
        "simple" | "simply" | "simplified" | "layman" | "layman's" | "beginner" | "beginners" | "eli5" => Simple,
        "technical" | "technically" | "advanced" | "expert" | "experts" => Technical,
        "only" | "solely" | "exclusively" | "nur" | "seulement" | "solo" | "solamente" | "apenas" => Only,
        "against" | "versus" | "vs" => Against,
        "accept" | "accepted" | "approve" | "approved" | "approval" => Accept,
        "reject" | "rejected" | "deny" | "denied" | "refuse" | "refused" => Reject,
        "cheap" | "cheaper" | "cheapest" | "inexpensive" | "affordable" => Cheap,
        "expensive" | "pricier" | "priciest" | "costly" => Expensive,
        "fast" | "faster" | "fastest" => Fast,
        "slow" | "slower" | "slowest" => Slow,
        "north" | "northern" => North,
        "south" | "southern" => South,
        "east" | "eastern" => East,
        "west" | "western" => West,
        "left" => Left,
        "right" => Right,
        _ => return None,
    })
}

/// ISO 639-1 code for a language name (English, native and some French, German, Spanish,
/// Italian and Portuguese names), or a programming language.
fn language(w: &str) -> Option<&'static str> {
    Some(match w {
        "english" | "inglés" | "ingles" | "anglais" | "englisch" | "inglese" | "inglês" => "en",
        "spanish" | "español" | "espanol" | "castellano" | "castilian" | "espagnol" | "spanisch" | "spagnolo"
        | "espanhol" => "es",
        "french" | "français" | "francais" | "francés" | "frances" | "französisch" | "francese" | "francês" => "fr",
        "german" | "deutsch" | "alemán" | "aleman" | "allemand" | "tedesco" | "alemão" => "de",
        "italian" | "italiano" | "italien" | "italienisch" => "it",
        "portuguese" | "português" | "portugues" | "portugués" | "portugais" | "portugiesisch" | "portoghese" => "pt",
        "dutch" | "nederlands" | "néerlandais" | "niederländisch" | "holandés" | "olandese" | "flemish" => "nl",
        "russian" | "русский" | "russe" | "russisch" | "ruso" | "russo" => "ru",
        "ukrainian" | "українська" | "ukrainien" | "ukrainisch" | "ucraniano" => "uk",
        "polish" | "polski" | "polonais" | "polnisch" | "polaco" => "pl",
        "czech" | "čeština" | "tchèque" | "tschechisch" => "cs",
        "slovak" | "slovenčina" => "sk",
        "hungarian" | "magyar" | "ungarisch" | "hongrois" => "hu",
        "romanian" | "română" | "roumain" | "rumänisch" | "rumano" => "ro",
        "bulgarian" | "български" => "bg",
        "croatian" | "hrvatski" => "hr",
        "serbian" | "српски" | "srpski" => "sr",
        "slovenian" | "slovene" | "slovenščina" => "sl",
        "greek" | "ελληνικά" | "grec" | "griechisch" | "griego" => "el",
        "turkish" | "türkçe" | "turc" | "türkisch" | "turco" => "tr",
        "arabic" | "العربية" | "arabe" | "arabisch" | "árabe" | "arabo" => "ar",
        "hebrew" | "עברית" | "hébreu" | "hebräisch" | "hebreo" => "he",
        "persian" | "farsi" | "فارسی" => "fa",
        "urdu" | "اردو" => "ur",
        "hindi" | "हिन्दी" | "हिंदी" => "hi",
        "bengali" | "bangla" | "বাংলা" => "bn",
        "tamil" | "தமிழ்" => "ta",
        "telugu" => "te",
        "marathi" => "mr",
        "punjabi" => "pa",
        "gujarati" => "gu",
        "chinese" | "mandarin" | "中文" | "汉语" | "漢語" | "普通话" | "chinois" | "chinesisch" | "chino"
        | "cinese" | "chinês" => "zh",
        "cantonese" | "粵語" | "广东话" => "yue",
        "japanese" | "日本語" | "japonais" | "japanisch" | "japonés" | "giapponese" | "japonês" => "ja",
        "korean" | "한국어" | "coréen" | "koreanisch" | "coreano" => "ko",
        "vietnamese" | "tiếng" => "vi",
        "thai" | "ไทย" => "th",
        "indonesian" | "bahasa" => "id",
        "malay" => "ms",
        "tagalog" | "filipino" => "tl",
        "swahili" | "kiswahili" => "sw",
        "swedish" | "svenska" | "suédois" | "schwedisch" => "sv",
        "norwegian" | "norsk" | "norvégien" | "norwegisch" => "no",
        "danish" | "dansk" | "danois" | "dänisch" => "da",
        "finnish" | "suomi" | "finnois" | "finnisch" => "fi",
        "icelandic" | "íslenska" => "is",
        "estonian" | "eesti" => "et",
        "latvian" | "latviešu" => "lv",
        "lithuanian" | "lietuvių" => "lt",
        "irish" | "gaeilge" => "ga",
        "welsh" | "cymraeg" => "cy",
        "catalan" | "català" => "ca",
        "basque" | "euskara" => "eu",
        "galician" | "galego" => "gl",
        "latin" | "latine" | "latein" => "la",
        "esperanto" => "eo",
        "afrikaans" => "af",
        "python" => "code:python",
        "javascript" | "js" => "code:javascript",
        "typescript" | "ts" => "code:typescript",
        "java" => "code:java",
        "kotlin" => "code:kotlin",
        "scala" => "code:scala",
        "rust" => "code:rust",
        "golang" => "code:go",
        "ruby" => "code:ruby",
        "php" => "code:php",
        "perl" => "code:perl",
        "swift" => "code:swift",
        "haskell" => "code:haskell",
        "elixir" => "code:elixir",
        "c++" | "cpp" => "code:cpp",
        "c#" | "csharp" => "code:csharp",
        "sql" => "code:sql",
        "bash" | "shell" | "powershell" => "code:shell",
        "html" => "code:html",
        "css" => "code:css",
        "json" => "code:json",
        "yaml" | "yml" => "code:yaml",
        "xml" => "code:xml",
        "csv" => "code:csv",
        "markdown" => "code:markdown",
        _ => return None,
    })
}

/// ISO 4217 codes in capitals, plus lower-case codes and names that are not ordinary words.
fn currency(t: &str, l: &str) -> Option<String> {
    const ISO: &[&str] = &[
        "AED", "AFN", "ALL", "AMD", "ANG", "AOA", "ARS", "AUD", "AWG", "AZN", "BAM", "BBD", "BDT", "BGN", "BHD", "BIF",
        "BMD", "BND", "BOB", "BRL", "BSD", "BTN", "BWP", "BYN", "BZD", "CAD", "CDF", "CHF", "CLP", "CNY", "COP", "CRC",
        "CUP", "CVE", "CZK", "DJF", "DKK", "DOP", "DZD", "EGP", "ERN", "ETB", "EUR", "FJD", "FKP", "GBP", "GEL", "GHS",
        "GIP", "GMD", "GNF", "GTQ", "GYD", "HKD", "HNL", "HTG", "HUF", "IDR", "ILS", "INR", "IQD", "IRR", "ISK", "JMD",
        "JOD", "JPY", "KES", "KGS", "KHR", "KMF", "KPW", "KRW", "KWD", "KYD", "KZT", "LAK", "LBP", "LKR", "LRD", "LSL",
        "LYD", "MAD", "MDL", "MGA", "MKD", "MMK", "MNT", "MOP", "MRU", "MUR", "MVR", "MWK", "MXN", "MYR", "MZN", "NAD",
        "NGN", "NIO", "NOK", "NPR", "NZD", "OMR", "PAB", "PEN", "PGK", "PHP", "PKR", "PLN", "PYG", "QAR", "RON", "RSD",
        "RUB", "RWF", "SAR", "SBD", "SCR", "SDG", "SEK", "SGD", "SHP", "SLE", "SOS", "SRD", "SSP", "STN", "SYP", "SZL",
        "THB", "TJS", "TMT", "TND", "TOP", "TRY", "TTD", "TWD", "TZS", "UAH", "UGX", "USD", "UYU", "UZS", "VES", "VND",
        "VUV", "WST", "XAF", "XAG", "XAU", "XCD", "XOF", "XPF", "YER", "ZAR", "ZMW", "ZWL", "BTC", "ETH", "USDT",
        "USDC",
    ];
    if t.len() <= 4 && t.chars().all(|c| c.is_ascii_uppercase()) {
        return ISO.contains(&t).then(|| l.to_owned());
    }
    Some(
        match l {
            "usd" | "dollar" | "dollars" | "usdollar" => "usd",
            "eur" | "euro" | "euros" => "eur",
            "gbp" | "sterling" | "quid" => "gbp",
            "jpy" | "yen" => "jpy",
            "cny" | "rmb" | "yuan" | "renminbi" => "cny",
            "chf" | "franc" | "francs" | "franken" => "chf",
            "inr" | "rupee" | "rupees" => "inr",
            "cad" => "cad",
            "aud" => "aud",
            "nzd" => "nzd",
            "sek" | "nok" | "dkk" | "krona" | "kronor" | "krone" | "kroner" => "kr",
            "pln" | "zloty" | "złoty" => "pln",
            "czk" | "koruna" => "czk",
            "huf" | "forint" => "huf",
            "rub" | "ruble" | "rubles" | "rouble" | "roubles" => "rub",
            "brl" | "reais" => "brl",
            "mxn" | "peso" | "pesos" => "peso",
            "zar" | "rand" => "zar",
            "krw" => "krw",
            "sgd" => "sgd",
            "hkd" => "hkd",
            "aed" | "dirham" | "dirhams" => "aed",
            "sar" | "riyal" | "riyals" => "sar",
            "ils" | "shekel" | "shekels" => "ils",
            "lira" | "lire" => "try",
            "btc" | "bitcoin" | "bitcoins" => "btc",
            "eth" | "ether" | "ethereum" => "eth",
            "usdt" | "tether" => "usdt",
            _ => return None,
        }
        .to_owned(),
    )
}

/// Canonical unit for a lower-cased unit word or abbreviation (counted only when the prompt has a
/// number).
fn unit(w: &str) -> Option<&'static str> {
    Some(match w {
        "km" | "kilometer" | "kilometers" | "kilometre" | "kilometres" | "kilómetros" | "kilomètres" => "km",
        "mi" | "mile" | "miles" | "millas" | "meilen" => "mi",
        "m" | "meter" | "meters" | "metre" | "metres" | "metros" | "mètres" => "m",
        "cm" | "centimeter" | "centimeters" | "centimetre" | "centimetres" => "cm",
        "mm" | "millimeter" | "millimeters" | "millimetre" | "millimetres" => "mm",
        "ft" | "foot" | "feet" => "ft",
        "inch" | "inches" => "in",
        "yd" | "yard" | "yards" => "yd",
        "kg" | "kilogram" | "kilograms" | "kilogramme" | "kilogrammes" | "kilo" | "kilos" => "kg",
        "g" | "gram" | "grams" | "gramme" | "grammes" | "gramos" => "g",
        "mg" | "milligram" | "milligrams" => "mg",
        "lb" | "lbs" | "pound" | "pounds" => "lb",
        "oz" | "ounce" | "ounces" => "oz",
        "t" | "ton" | "tons" | "tonne" | "tonnes" => "t",
        "l" | "liter" | "liters" | "litre" | "litres" | "litros" => "l",
        "ml" | "milliliter" | "milliliters" | "millilitre" | "millilitres" => "ml",
        "gal" | "gallon" | "gallons" => "gal",
        "c" | "celsius" | "centigrade" => "°c",
        "f" | "fahrenheit" => "°f",
        "k" | "kelvin" => "k",
        "mph" => "mph",
        "kph" | "kmh" => "kmh",
        "b" | "byte" | "bytes" => "b",
        "kb" | "kib" | "kilobyte" | "kilobytes" => "kb",
        "mb" | "mib" | "megabyte" | "megabytes" => "mb",
        "gb" | "gib" | "gigabyte" | "gigabytes" => "gb",
        "tb" | "tib" | "terabyte" | "terabytes" => "tb",
        "ms" | "millisecond" | "milliseconds" => "ms",
        "s" | "sec" | "secs" | "second" | "seconds" => "s",
        "min" | "mins" | "minute" | "minutes" => "min",
        "h" | "hr" | "hrs" | "hour" | "hours" | "stunden" | "heures" | "horas" | "ore" => "h",
        "day" | "days" | "tage" | "jours" | "días" | "dias" | "giorni" => "d",
        "week" | "weeks" | "wochen" | "semaines" | "semanas" | "settimane" => "wk",
        "month" | "months" | "monate" | "mois" | "meses" | "mesi" => "mo",
        "year" | "years" | "yr" | "yrs" | "jahre" | "ans" | "años" | "anni" | "anos" => "yr",
        "percent" | "percentage" | "prozent" | "pourcent" => "%",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn same(a: &str, b: &str) -> bool {
        signature(a) == signature(b)
    }

    /// The three false hits of the AWS run (`bench/RESULTS-aws-2026-10.md`, semantic cache end to
    /// end at threshold 0.95), and the other near-misses of its adversarial set.
    #[test]
    fn near_misses_differ() {
        for (a, b) in [
            ("Translate 'good morning' into Spanish.", "Translate 'good morning' into Italian."),
            ("Convert 100 USD to EUR.", "Convert 100 EUR to USD."),
            ("Explain the CAP theorem briefly.", "Explain the CAP theorem in detail."),
            ("Show expense reports over 5000 EUR", "Show expense reports over 500 EUR"),
            ("Convert 100 USD to EUR.", "Convert 1000 USD to EUR."),
            ("What is the status of order 12345?", "What is the status of order 12346?"),
            ("What were total sales for Q3 2025?", "What were total sales for Q3 2024?"),
            ("How do I enable two-factor authentication?", "How do I disable two-factor authentication?"),
            ("Which customers renewed this year?", "Which customers did not renew this year?"),
            ("Which customers renewed this year?", "Which customers never renewed this year?"),
            ("How can I increase the cache size?", "How can I decrease the cache size?"),
            ("Book a flight from Paris to London", "Book a flight from London to Paris"),
            ("Convert 10 miles to km", "Convert 10 km to miles"),
            ("What's the euro to dollar exchange rate?", "What's the dollar to euro exchange rate?"),
            ("List the largest invoices", "List the smallest invoices"),
            ("Sort the users in ascending order", "Sort the users in descending order"),
            ("How do I log in to the portal?", "How do I log out of the portal?"),
            ("Show expense reports above the limit", "Show expense reports below the limit"),
            ("Write a positive review of the hotel", "Write a negative review of the hotel"),
            ("What is the weather today in Berlin?", "What is the weather tomorrow in Berlin?"),
            ("Summarize the email from Alice", "Summarize the email from Bob"),
            ("Erkläre das kurz", "Erkläre das ausführlich"),
            ("Explica el teorema CAP brevemente", "Explica el teorema CAP en detalle"),
            ("Convert this Python script to JavaScript", "Convert this JavaScript script to Python"),
            ("How do I add a user to the group?", "How do I remove a user from the group?"),
            ("Send me the report", "Don't send me the report"),
            ("Translate this into español", "Translate this into français"),
            ("Il faut le faire", "Il ne faut pas le faire"),
        ] {
            assert!(!same(a, b), "must not share an answer: {a:?} vs {b:?}\n{:?}\n{:?}", signature(a), signature(b));
        }
    }

    /// Paraphrases that must still be able to hit (the embedding threshold decides).
    #[test]
    fn paraphrases_match() {
        for (a, b) in [
            ("Translate 'good morning' into Spanish.", "How do you say 'good morning' in Spanish?"),
            ("Translate 'good morning' into Spanish.", "How would I say \"good morning\" in Spanish?"),
            ("Explain the CAP theorem briefly.", "Give me a brief explanation of the CAP theorem."),
            ("Explain the CAP theorem in detail.", "Give a detailed explanation of the CAP theorem."),
            ("Convert 100 USD to EUR.", "How much is 100 USD in EUR?"),
            ("Convert 100 USD to EUR.", "What is 100 USD in euros?"),
            ("hi, how do i reset my pasword", "How do I reset my password?"),
            ("What was revenue in Q3 2025?", "revenue in Q3 2025?"),
            ("How do I enable two-factor authentication?", "How can I turn on two-factor authentication?"),
            ("How many vacation days do new employees get?", "How much annual leave do new hires get?"),
            ("What is our refund policy?", "Can you tell me the refund policy?"),
            ("Summarize this article in French.", "Give me a French summary of this article."),
            ("Wie setze ich mein Passwort zurück?", "Wie kann ich mein Passwort zurücksetzen?"),
            ("What is the capital of France?", "Which city is the capital of France?"),
            ("I'm locked out, how do I reset my password?", "how do I reset my password? I'm locked out"),
            ("如何重置我的密码？", "我怎样重置密码？"),
            ("Why is the sky blue?", "What makes the sky blue?"),
        ] {
            assert!(same(a, b), "must be comparable: {a:?} vs {b:?}\n{:?}\n{:?}", signature(a), signature(b));
        }
    }

    #[test]
    fn slots_keep_order_numbers_codes_and_names() {
        let s = signature("Revenue for Q3 2025, region EMEA-2 (v1.2), in USD for Acme.");
        assert_eq!(s.slots, ["q3", "2025", "emea", "2", "v1.2", "usd", "acme"]);
        assert!(signature("what is the capital of france").slots.is_empty());
        assert_eq!(signature("1,000 or 1000").slots, ["1,000", "1000"]);
        assert_eq!(signature("Price in € and $").slots, ["€", "$"]);
        assert_eq!(signature("Translate into Spanish").slots, ["lang:es"]);
        assert_eq!(signature("traduce al español").slots, ["lang:es"]);
        assert_eq!(signature("Run 5 km in 30 minutes").slots, ["5", "km", "30", "min"]);
        assert!(signature("how many days of leave").slots.is_empty(), "units only count next to numbers");
        assert_eq!(signature("explain briefly, not in detail").modifier_names(), ["negation", "brief", "detailed"]);
    }

    #[test]
    fn signature_is_fast() {
        let text = "Please draft a short follow-up note to our customer about the renewal. Their contact is \
                    jane.doe@acme.com and the card on file is 4111 1111 1111 1111. Keep it friendly and under one \
                    hundred words, and mention that the invoice is attached.";
        // Best of several batches, so a loaded machine does not fail the test.
        let n = 200;
        let per = (0..10)
            .map(|_| {
                let started = std::time::Instant::now();
                for _ in 0..n {
                    std::hint::black_box(signature(std::hint::black_box(text)));
                }
                started.elapsed() / n
            })
            .min()
            .unwrap_or_default();
        eprintln!("guard signature: {per:?} per prompt (best of 10 batches)");
        // Typically a few microseconds in release builds; generous for debug builds and CI.
        assert!(per < std::time::Duration::from_millis(1), "{per:?} per signature");
    }
}
