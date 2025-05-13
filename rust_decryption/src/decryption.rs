use aead::Aead;
use base64::{engine::general_purpose, Engine};
use chacha20poly1305::{
    aead::{self, NewAead},
    ChaCha20Poly1305, Key, Nonce,
};
use alloy::primitives::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac, NewMac};
use ic_bls12_381::{pairing, G1Affine, G2Affine};
use revm::{
    precompile::PrecompileError,
    primitives::{
       PrecompileOutput, PrecompileResult
    },
};
use std::io::Cursor;
use std::io::Read;
use std::io::Write;
use std::io::{self, BufRead, BufReader};
use ic_bls12_381::{G1Projective, Scalar};
use sha2::{Digest, Sha256};

/////////////////////////////
/// Constants and Structs ///
/////////////////////////////


const BLOCK_SIZE: usize = 32;
const INTRO: &str = "age-encryption.org/v1";
const RECIPIENT_PREFIX: &[u8] = b"->";
const FOOTER_PREFIX: &[u8] = b"---";
const COLUMNS_PER_LINE: usize = 64;
const BYTES_PER_LINE: usize = COLUMNS_PER_LINE / 4 * 3;
const KYBER_POINT_LEN: usize = 48;
const CIPHER_V_LEN: usize = 32;
const CIPHER_W_LEN: usize = 32;

fn dist_ibe_fn(input: &Bytes, target_gas: u64) -> PrecompileResult {
    let (c, sk) = parse_abi(input)?;
    decrypt(c, sk, target_gas)
  }
  

pub fn parse_abi(input: &Bytes) -> Result<(Vec<u8>, Vec<u8>), PrecompileError> {
    if input.len() < 96 {
        return Err(PrecompileError::other("Invalid input length").into());
    }
    let c = input[0..input.len() - 96].to_vec();
    let skbytes = input[input.len() - 96..].to_vec();
    Ok((c, skbytes))
}

struct Header {
    recipients: Vec<Box<Stanza>>,
    mac: Vec<u8>,
}

impl Header {
    fn marshal_without_mac<W: Write>(&self, w: &mut W) -> io::Result<()> {
        writeln!(w, "{}", INTRO)?;
        for r in &self.recipients {
            r.marshal(w);
        }
        write!(w, "{}", "---")
    }
}

#[derive(Clone)]
struct Stanza {
    type_: String,
    args: Vec<String>,
    body: Vec<u8>,
}
impl Stanza {
    fn marshal<W: Write>(&self, w: &mut W) -> io::Result<()> {
        write!(w, "->")?;
        write!(w, " {}", self.type_)?;
        for arg in &self.args {
            write!(w, " {}", arg)?;
        }
        writeln!(w)?;
        let encoded = general_purpose::STANDARD_NO_PAD.encode(&self.body);
        for chunk in encoded.as_bytes().chunks(64) {
            w.write_all(chunk)?;
            writeln!(w)?;
        }
        Ok(())
    }
}
struct HmacWriter(Hmac<Sha256>);

impl HmacWriter {
    fn new(hmac: Hmac<Sha256>) -> Self {
        HmacWriter(hmac)
    }
}

impl Write for HmacWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

////////////////////////
/// Entry Point ////////
////////////////////////

pub fn decrypt(c: Vec<u8>, skbytes: Vec<u8>,  gas_limit: u64) -> PrecompileResult {
    if skbytes.len() != 96 {
        return Err(PrecompileError::other("Invalid compressed G2Affine length").into());
    }
    let sk_ct_option = G2Affine::from_compressed(&skbytes.try_into().unwrap());
    if sk_ct_option.is_none().into() {
        return Err(PrecompileError::other("Invalid compressed G2Affine").into());
    }
    let sk = sk_ct_option.unwrap();

    let mut cursor = Cursor::new(c);

    let decrypted = decrypter(&sk, &mut cursor)?;
    Ok(PrecompileOutput::new(gas_limit, decrypted.into()))
  
}
pub fn decrypter<'a>(
    sk: &G2Affine,
    src: &'a mut dyn Read,
) -> core::result::Result<Vec<u8>, PrecompileError> {
    let (hdr, mut payload) = parse(src).unwrap();

    let file_key = unwrap(sk, &[*hdr.recipients[0].clone()])?;

    let mac = headermac(file_key.clone(), hdr.recipients[0].clone().body)
        .map_err(|_| (PrecompileError::other("MAC contract error").into()))?;

    if mac.to_vec() != hdr.mac {
        return Err(PrecompileError::other("MACs not matching").into());
    }
    let mut nonce = vec![0u8; 16];

    let _ = payload
        .read_exact(&mut nonce)
        .map_err(|_| (PrecompileError::other("Payload reading error").into()))?;

    let mut ciphertext: Vec<u8> = vec![];
    let output = payload.read_to_end(&mut ciphertext);
    if output.is_err() {
        return Err(PrecompileError::other("Payload reading error").into());
    }

    let msg = chach20_decrypter(file_key.clone(), nonce, ciphertext)
        .map_err(|_| (PrecompileError::other("Chacha20 decryption contract error").into()));

    msg
}
fn headermac(key: Vec<u8>, body: Vec<u8>) -> Result<Vec<u8>, PrecompileError> {
    if key.len() != 32 || body.is_empty() {
        return Err(PrecompileError::other("Wrong input length").into());
    }

    let result = Stanza {
        type_: "distIBE".to_string(),
        args: vec![],
        body,
    };
    let hdr = Header {
        recipients: vec![Box::new(result)],
        mac: vec![],
    };

    let h = Hkdf::<Sha256>::new(None, &key);
    let mut hmac_key = [0u8; 32];
    h.expand(b"header", &mut hmac_key)
        .map_err(|_| (PrecompileError::other("Key error").into()))?;

    let mut hh = Hmac::<Sha256>::new_from_slice(&hmac_key)
        .map_err(|_| (PrecompileError::other("Hash error").into()))?;
    let mut hmac_writer = HmacWriter::new(hh.clone());

    hdr.marshal_without_mac(&mut hmac_writer)
        .map_err(|_| (PrecompileError::other("Header error").into()))?;

    hh = hmac_writer.0;
    Ok(hh.finalize().into_bytes().to_vec())
}

fn chach20_decrypter(
    key: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, PrecompileError> {
    if key.len() != 32 || nonce.len() != 16 || ciphertext.len() < 2 {
        return Err(PrecompileError::other("Wrong input length").into());
    }
    let key = stream_key(key.as_slice(), nonce.as_slice());
    let aead_key = Key::from_slice(key.as_slice());
    let chacha20 = ChaCha20Poly1305::new(aead_key);
    let n = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let plain = chacha20
        .decrypt(&Nonce::from_slice(&n), &ciphertext[0..])
        .map_err(|_| (PrecompileError::other("decryption error").into()))?;

    Ok(plain)
}

fn unwrap(sk: &G2Affine, stanzas: &[Stanza]) -> core::result::Result<Vec<u8>, PrecompileError> {
    let exp_len = KYBER_POINT_LEN + CIPHER_V_LEN + CIPHER_W_LEN;
    if stanzas.len() != 1 && stanzas[0].body.len() != exp_len {
        return Err(PrecompileError::other("Wrong length").into());
    }
    let kyber_point = &stanzas[0].body[0..KYBER_POINT_LEN];
    let cipher_v = &stanzas[0].body[KYBER_POINT_LEN..KYBER_POINT_LEN + CIPHER_V_LEN];
    let cipher_w = &stanzas[0].body[KYBER_POINT_LEN + CIPHER_V_LEN..];

    let u: G1Affine = G1Affine::from_compressed(kyber_point.try_into().unwrap()).unwrap();

    let r_gid = pairing(&u, sk);

    let data = ibe_decrypt(
        r_gid.to_bytes().to_vec(),
        cipher_v.to_vec().clone(),
        cipher_w.to_vec().clone(),
        u.to_compressed().to_vec(),
    );

    data
}
pub fn ibe_decrypt(
    r_gid: Vec<u8>,
    cv: Vec<u8>,
    cw: Vec<u8>,
    cu: Vec<u8>,
) -> Result<Vec<u8>, PrecompileError> {
    if cu.len() != 48 || cv.len() > BLOCK_SIZE || cw.len() > BLOCK_SIZE {
        return Err(PrecompileError::other("Invalid input length").into());
    }

    let sigma = {
        let mut hash = sha2::Sha256::new();

        hash.update(b"IBE-H2");
        hash.update(r_gid);

        let h_r_git: &[u8] = &hash.finalize().to_vec()[0..32];

        xor(h_r_git, &cv)
    };

    let msg = {
        let mut hash = sha2::Sha256::new();
        hash.update(b"IBE-H4");
        hash.update(&sigma);
        let h_sigma = &hash.finalize()[0..BLOCK_SIZE];
        xor(h_sigma, &cw)
    };

    let verify_res = verify(sigma.clone(), msg.clone(), cu)
        .map_err(|_| (PrecompileError::other("Hasher error").into()))?;

    if !verify_res {
        return Err(PrecompileError::other("Verfication failed").into());
    }

    Ok(msg)
}

pub fn verify(sigma: Vec<u8>, msg: Vec<u8>, cu: Vec<u8>) -> Result<bool, PrecompileError> {
    if sigma.len() != 32 || msg.len() != 32 || cu.len() != 48 {
        return Err(PrecompileError::other("Invalid input length").into());
    }

    let r_g = {
        let r = h3(sigma.to_vec(), msg.to_vec())?;
        let rs_ct = Scalar::from_bytes(&r.try_into().unwrap());
        if rs_ct.is_some().unwrap_u8() == 0 {
            return Err(PrecompileError::other("Error deserializing the scalar").into());
        }
        let rs = rs_ct.unwrap();
        let g1_base_projective = G1Projective::from(G1Affine::generator());
        g1_base_projective * rs
    };

    let result_affine = G1Affine::from(r_g);
    Ok(result_affine.to_compressed().to_vec() == cu)
}


////////////////////////////////
/////// Helper functions ///////
///////////////////////////////

fn stream_key(key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let h = Hkdf::<Sha256>::new(Some(nonce), key);
    let mut stream_key = vec![0u8; 32];

    h.expand(b"payload", &mut stream_key)
        .expect("age: internal error: failed to read from HKDF");

    stream_key
}

fn split_args(line: &[u8]) -> (String, Vec<String>) {
    let line_str = String::from_utf8_lossy(line);
    let trimmed_line = line_str.trim_end_matches('\n');
    let parts: Vec<String> = trimmed_line.split_whitespace().map(String::from).collect();

    if !parts.is_empty() {
        (parts[0].clone(), parts[1..].to_vec())
    } else {
        (String::new(), Vec::new())
    }
}

fn decode_string(s: &str) -> Vec<u8> {
    let decoded = general_purpose::STANDARD_NO_PAD.decode(s);
    if decoded.is_err() {
        return vec![];
    }
    return decoded.unwrap();
}

fn parse<'a, R: Read + 'a>(input: R) -> io::Result<(Header, Box<dyn Read + 'a>)> {
    let mut rr = BufReader::new(input);
    let mut line = String::new();

    rr.read_line(&mut line)?;
    if line.trim_end() != INTRO {}

    let mut h = Header {
        recipients: Vec::new(),
        mac: Vec::new(),
    };
    let mut r: Option<Stanza> = None;

    loop {
        let mut line_bytes = Vec::new();
        let bytes_read = rr.read_until(b'\n', &mut line_bytes)?;
        if bytes_read == 0 {
            break;
        }

        let line = String::from_utf8_lossy(&line_bytes).into_owned();

        if line.as_bytes().starts_with(FOOTER_PREFIX) {
            let (prefix, args) = split_args(&line.as_bytes());
            if prefix.as_bytes() != FOOTER_PREFIX || args.len() != 1 {}
            h.mac = decode_string(&args[0]);
            break;
        } else if line.as_bytes().starts_with(RECIPIENT_PREFIX) {
            r = Some(Stanza {
                type_: String::new(),
                args: Vec::new(),
                body: Vec::new(),
            });
            let (_, args) = split_args(&line.as_bytes());

            let stanza = r.as_mut().unwrap();
            stanza.type_ = args[0].clone();
            stanza.args = args[1..].to_vec();

            h.recipients.push(Box::new(stanza.clone()));
        } else if let Some(_stanza) = r.as_mut() {
            let b = decode_string(&line.trim_end());
            if b.len() > BYTES_PER_LINE {}
            h.recipients[0].body.extend_from_slice(&b);

            if b.len() < BYTES_PER_LINE {
                r = None;
            }
        } else {
        }
    }

    let payload = if rr.buffer().is_empty() {
        Box::new(rr.into_inner()) as Box<dyn Read>
    } else {
        let buffer = rr.buffer().to_vec();
        let remaining_input = rr.into_inner();
        Box::new(io::Cursor::new(buffer).chain(remaining_input)) as Box<dyn Read>
    };

    Ok((h, payload))
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(a, b)| a ^ b).collect()
}
pub fn h3(sigma: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, PrecompileError> {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"IBE-H3");
    hasher.update(&sigma);
    hasher.update(&msg);
    let initial_hash = hasher.finalize_reset();

    for i in 1..=65535u16 {
        hasher.update(&i.to_le_bytes());
        hasher.update(&initial_hash);
        let mut hashed = hasher.finalize_reset().to_vec();

        hashed[0] /= 2;
        hashed.reverse();

        let scalar_option = Scalar::from_bytes(&hashed[..32].try_into().unwrap());
        if scalar_option.is_some().into() {
            return Ok(hashed[..32].to_vec());
        }
    }

    Err(PrecompileError::other("Hashing error").into())
}
