// #[derive(Debug, Clone, Eq, PartialEq)]
// pub enum Content<'a> {
//     Borrowed(&'a [u8]),
//     Owned(Vec<u8>),
// }

// impl<'a> Content<'a> {
//     pub fn bytes(&self) -> &[u8] {
//         match self {
//             Self::Borrowed(bytes) => bytes,
//             Self::Owned(bytes) => bytes,
//         }
//     }

//     pub fn to_owned(self) -> Content<'static> {
//         Content::Owned(match self {
//             Self::Borrowed(bytes) => bytes.to_vec(),
//             Self::Owned(bytes) => bytes,
//         })
//     }

//     pub fn from_slice(s: &'a [u8]) -> Self{
//         Content::Borrowed(s)
//     }

//     pub fn from_vec(v: Vec<u8>)-> Self{    
//         Content::Owned(v)
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::Content;

//     #[test]
//     fn test_content() {
//         let b = [1; 32];
//         let a = Content::Borrowed(&b[..2]);
//         let aa = a.to_owned();
//         println!("aa: {:?}", aa);
//     }
// }
