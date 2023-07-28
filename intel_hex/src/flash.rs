use crate::common::Chunk;

pub fn flash_blocks<I, const N: usize>(chunks_iter: I) -> FlashBlocks<I,N>
where I: Iterator<Item=Chunk>
{
    FlashBlocks::new(chunks_iter)
}

pub struct FlashBlocks<I: Iterator<Item=Chunk>, const N: usize> {
    chunks_iter: I,
    cached_chunk: Option<Chunk>,
}

impl<I: Iterator<Item=Chunk>, const N: usize> FlashBlocks<I,N> {
    fn new(chunks_iter: I) -> Self {
        FlashBlocks { chunks_iter, cached_chunk: None }
    }

    fn next_chunk(&mut self) -> Option<Chunk> {
        if let Some(chunk) = self.cached_chunk.take() {
            Some(chunk)
        } else {
            self.chunks_iter.next()
        }
    }

    fn addr_of_block_containing(chunk: &Chunk) -> u32 {
        (chunk.addr / N as u32) * N as u32
    }
}

impl<I: Iterator<Item=Chunk>, const N: usize> Iterator for FlashBlocks<I,N> {
    type Item=FlashBlock<N>;

    fn next(&mut self) -> Option<Self::Item> {
        let chunk = match self.next_chunk() {
            Some(chunk) => chunk,
            None => return None,
        };
        let mut block = FlashBlock::new(Self::addr_of_block_containing(&chunk));
        self.cached_chunk = block.store_chunk(chunk);

        loop {
            if block.last_byte_set() {
                // Chunks are returned from chunks_iter in ascending order by address.
                // If we've set the last byte in this block, the next chunk can't
                // possibly be stored in this same block.
                return Some(block);
            }
            let chunk = match self.next_chunk() {
                Some(chunk) => chunk,
                None => return Some(block),
            };
            if block.contains_addr(chunk.addr) {
                self.cached_chunk = block.store_chunk(chunk);
            } else {
                self.cached_chunk = Some(chunk);
                return Some(block);
            }
        }
    }
}

pub struct FlashBlock<const N: usize> {
    pub addr: u32,
    data: [u8; N],
    initialized: [bool; N],
}

impl<const N: usize> FlashBlock<N> {
    fn new(addr: u32) -> Self {
        assert!(addr % N as u32 == 0, "Flash block address must be aligned to the size of a flash block");
        FlashBlock { addr, data: [0xff; N], initialized: [false; N] }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn initialized(&self) -> &[bool] {
        &self.initialized
    }

    fn contains_addr(&self, addr: u32) -> bool {
        addr >= self.addr && addr < self.addr + N as u32
    }

    fn last_byte_set(&self) -> bool {
        self.initialized[N-1]
    }

    fn store_chunk(&mut self, chunk: Chunk) -> Option<Chunk> {
        assert!(self.contains_addr(chunk.addr));
        use std::cmp::min;
        let offset = (chunk.addr - self.addr) as usize;
        let count = min(chunk.len(), N - offset);
        self.data[offset..offset+count].copy_from_slice(&chunk.data()[..count]);
        self.initialized[offset..offset+count].iter_mut().for_each(|flag| *flag = true);
        
        if count < chunk.len() {
            let excess_chunk = Chunk { addr: chunk.addr + count as u32, data: chunk.data()[count..].to_vec() };
            Some(excess_chunk)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_chunk_not_at_end() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 0, data: vec![1, 2, 3, 4, 5] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 1);
        assert_eq!(blocks[0].data(), &[1, 2, 3, 4, 5, 0xff, 0xff]);
        assert_eq!(blocks[0].initialized(), &[true, true, true, true, true, false, false]);
    }

    #[test]
    fn single_chunk_at_end() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 2, data: vec![1, 2, 3, 4, 5] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 1);
        assert_eq!(blocks[0].data(), &[0xff, 0xff, 1, 2, 3, 4, 5]);
        assert_eq!(blocks[0].initialized(), &[false, false, true, true, true, true, true]);
    }

    #[test]
    fn single_chunk_overflows_once() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 4, data: vec![1, 2, 3, 4, 5] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 2);

        assert_eq!(blocks[0].data(), &[0xff, 0xff, 0xff, 0xff, 1, 2, 3]);
        assert_eq!(blocks[0].initialized(), &[false, false, false, false, true, true, true]);

        assert_eq!(blocks[1].data(), &[4, 5, 0xff, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(blocks[1].initialized(), &[true, true, false, false, false, false, false]);
    }

    #[test]
    fn single_chunk_overflows_twice() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 4, data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 3);

        assert_eq!(blocks[0].data(), &[0xff, 0xff, 0xff, 0xff, 1, 2, 3]);
        assert_eq!(blocks[0].initialized(), &[false, false, false, false, true, true, true]);

        assert_eq!(blocks[1].data(), &[4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(blocks[1].initialized(), &[true, true, true, true, true, true, true]);

        assert_eq!(blocks[2].data(), &[11, 12, 13, 14, 0xff, 0xff, 0xff]);
        assert_eq!(blocks[2].initialized(), &[true, true, true, true, false, false, false]);
    }

    #[test]
    fn multiple_chunks_not_at_end() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 0, data: vec![1, 2] });
        chunks.push(Chunk { addr: 2, data: vec![3, 4] });
        chunks.push(Chunk { addr: 4, data: vec![5, 6] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 1);
        assert_eq!(blocks[0].data(), &[1, 2, 3, 4, 5, 6, 0xff]);
        assert_eq!(blocks[0].initialized(), &[true, true, true, true, true, true, false]);
    }

    #[test]
    fn multiple_chunks_end() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 1, data: vec![1, 2] });
        chunks.push(Chunk { addr: 3, data: vec![3, 4] });
        chunks.push(Chunk { addr: 5, data: vec![5, 6] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 1);
        assert_eq!(blocks[0].data(), &[0xff, 1, 2, 3, 4, 5, 6]);
        assert_eq!(blocks[0].initialized(), &[false, true, true, true, true, true, true]);
    }

    #[test]
    fn multiple_chunks_overflows_once() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 1, data: vec![1, 2] });
        chunks.push(Chunk { addr: 3, data: vec![3, 4] });
        chunks.push(Chunk { addr: 5, data: vec![5, 6, 7, 8, 9] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 2);

        assert_eq!(blocks[0].data(), &[0xff, 1, 2, 3, 4, 5, 6]);
        assert_eq!(blocks[0].initialized(), &[false, true, true, true, true, true, true]);

        assert_eq!(blocks[1].data(), &[7, 8, 9, 0xff, 0xff, 0xff, 0xff]);
        assert_eq!(blocks[1].initialized(), &[true, true, true, false, false, false, false]);
    }

    #[test]
    fn multiple_chunks_overflows_twice() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 1, data: vec![1, 2] });
        chunks.push(Chunk { addr: 3, data: vec![3, 4] });
        chunks.push(Chunk { addr: 5, data: vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 3);

        assert_eq!(blocks[0].data(), &[0xff, 1, 2, 3, 4, 5, 6]);
        assert_eq!(blocks[0].initialized(), &[false, true, true, true, true, true, true]);

        assert_eq!(blocks[1].data(), &[7, 8, 9, 10, 11, 12, 13]);
        assert_eq!(blocks[1].initialized(), &[true, true, true, true, true, true, true]);

        assert_eq!(blocks[2].data(), &[14, 15, 16, 17, 0xff, 0xff, 0xff]);
        assert_eq!(blocks[2].initialized(), &[true, true, true, true, false, false, false]);
    }

    #[test]
    fn non_contigous_chunks() {
        let mut chunks = Vec::new();
        chunks.push(Chunk { addr: 1, data: vec![1, 2, 3, 4, 5] });
        chunks.push(Chunk { addr: 18, data: vec![6, 7, 8] });

        let blocks: Vec<_> = flash_blocks::<_,7>(chunks.into_iter()).collect();
        assert!(blocks.len() == 2);

        assert!(blocks[0].addr == 0);
        assert_eq!(blocks[0].data(), &[0xff, 1, 2, 3, 4, 5, 0xff]);
        assert_eq!(blocks[0].initialized(), &[false, true, true, true, true, true, false]);

        assert!(blocks[1].addr == 14);
        assert_eq!(blocks[1].data(), &[0xff, 0xff, 0xff, 0xff, 6, 7, 8]);
        assert_eq!(blocks[1].initialized(), &[false, false, false, false, true, true, true]);
    }
}