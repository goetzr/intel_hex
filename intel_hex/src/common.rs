use std::fmt;

pub struct Record {
    pub addr: u16,
    pub kind: RecordKind,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum RecordKind {
    Data,
    EndOfFile,
    ExtendedSegmentAddress,
    StartSegmentAddress,
    ExtendedLinearAddress,
    StartLinearAddress,
}

impl RecordKind {
    pub fn from_int(kind: u8) -> Option<Self> {
        use RecordKind::*;
        match kind {
            0 => Some(Data),
            1 => Some(EndOfFile),
            2 => Some(ExtendedSegmentAddress),
            3 => Some(StartSegmentAddress),
            4 => Some(ExtendedLinearAddress),
            5 => Some(StartLinearAddress),
            _ => None,
        }
    }
}

impl fmt::Display for RecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use RecordKind::*;
        match self {
            Data => write!(f, "Data"),
            EndOfFile => write!(f, "EndOfFile"),
            ExtendedSegmentAddress => write!(f, "ExtendedSegmentAddress"),
            StartSegmentAddress => write!(f, "StartSegmentAddress"),
            ExtendedLinearAddress => write!(f, "ExtendedLinearAddress"),
            StartLinearAddress => write!(f, "StartLinearAddress"),
        }
    }
}

pub struct Chunk {
    pub addr: u32,
    pub(crate) data: Vec<u8>,
}

impl Chunk {
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::path::PathBuf;
    use std::process;
    use std::sync::OnceLock;

    static WORKSPACE_PATH: OnceLock<PathBuf> = OnceLock::new();

    pub fn test_file_path(name: &str) -> PathBuf {
        let workspace_path = WORKSPACE_PATH.get_or_init(|| {
            let output = process::Command::new(env!("CARGO"))
                .arg("locate-project")
                .arg("--workspace")
                .arg("--message-format=plain")
                .output()
                .unwrap()
                .stdout;
            let cargo_toml_path = String::from_utf8(output).unwrap();
            PathBuf::from(cargo_toml_path).join("..")
        });

        let mut file_path = workspace_path.clone();
        file_path.push("test_files");
        file_path.push(name);
        file_path
    }
}