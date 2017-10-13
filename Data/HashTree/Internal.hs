{-# LANGUAGE OverloadedStrings #-}

module Data.HashTree.Internal (
    Settings(..)
  , defaultSettings
  , MerkleHashTrees(..)
  , size
  , digest
  , empty
  , fromList
  , fromList'
  , add
  , InclusionProof(..)
  , generateInclusionProof
  , verifyingInclusionProof
  ) where

import Crypto.Hash
import Data.Bits
import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as BA
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Char8 ()
import Data.List (foldl')
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map

----------------------------------------------------------------

-- | Settings for Merkle Hash Trees.
--   The first parameter is input data type.
--   The second one is digest data type.
--
-- To create this, use 'defaultSettings':
--
-- > defaultSettings { hash0 = ..., hash1 = ..., hash2 = ... }
data Settings inp ha = Settings {
    -- | A hash value for non input element.
    hash0 :: Digest ha
    -- | A hash function for one input element.
  , hash1 :: inp -> Digest ha
    -- | A hash function for two input elements.
  , hash2 :: Digest ha -> Digest ha -> Digest ha
  }

sha256 :: ByteString -> Digest SHA256
sha256 = hash

-- | A default Settings with 'ByteString' and 'SHA256'.
--   This can be used for CT(Certificate Transparency) defined in RFC 6962.
defaultSettings :: Settings ByteString SHA256
defaultSettings = Settings {
    hash0 = sha256 ""
  , hash1 = \x -> sha256 (BS.singleton 0x00 `BS.append` x)
  , hash2 = \x y -> sha256 $ BS.concat [BS.singleton 0x01, BA.convert x, BA.convert y]
  }

----------------------------------------------------------------

-- | The position of the target element from 0.
type Index = Int

-- | The data type for Merkle Hash Trees.
--   The first parameter is input data type.
--   The second one is digest data type.
data MerkleHashTrees inp ha = MerkleHashTrees {
    settings :: !(Settings inp ha)
  , hashtree :: !(HashTree inp ha)
  , indices  :: !(Map (Digest ha) Index)
  }

-- | Getting the size
size :: MerkleHashTrees inp ha -> Int
size = treeSize . hashtree

-- | Getting the Merkle Tree Hash.
digest :: MerkleHashTrees inp ha -> Digest ha
digest = value . hashtree

----------------------------------------------------------------

data HashTree inp ha =
    Empty !(Digest ha)
  | Leaf  !(Digest ha) !Index inp
  | Node  !(Digest ha) !Index !Index !(HashTree inp ha) !(HashTree inp ha)
  deriving (Eq, Show)

-- | Creating an empty 'MerkleHashTrees'.
empty :: Settings inp ha -> MerkleHashTrees inp ha
empty set = MerkleHashTrees set (Empty (hash0 set)) Map.empty

treeSize :: HashTree inp ha -> Int
treeSize (Empty _) = 0
treeSize ht        = idxr ht + 1

value :: HashTree inp ha -> Digest ha
value (Empty ha)         = ha
value (Leaf  ha _ _)     = ha
value (Node  ha _ _ _ _) = ha

----------------------------------------------------------------

idxl :: HashTree inp ha -> Index
idxl (Leaf _ i _)     = i
idxl (Node _ i _ _ _) = i
idxl _                = error "idxl"

idxr :: HashTree inp ha -> Index
idxr (Leaf _ i _)     = i
idxr (Node _ _ i _ _) = i
idxr (Empty _)        = error "idxr"

----------------------------------------------------------------

-- | Creating a Merkle Hash Tree from a list of elements. O(n log n)
fromList :: (ByteArrayAccess inp, HashAlgorithm ha)
         => Settings inp ha -> [inp] -> MerkleHashTrees inp ha
fromList set xs = foldl' (flip add) (empty set) xs

-- | Adding (appending) an element. O(log n)
add :: (ByteArrayAccess inp, HashAlgorithm ha)
     => inp -> MerkleHashTrees inp ha -> MerkleHashTrees inp ha
add a mht@(MerkleHashTrees set ht idb) = case Map.lookup hx idb of
    Just _  -> mht
    Nothing -> MerkleHashTrees set ht' idb'
  where
    idb' = Map.insert hx ix idb

    hx = hash1 set a
    ix = treeSize ht
    x = Leaf hx ix a

    ht' = ins ht
    hash2' = hash2 set
    ins (Empty _)           = x
    ins l@(Leaf hl il _ )   = Node (hash2' hl hx) il ix l x
    ins t@(Node h il ir l r)
      | isPowerOf2 siz = Node (hash2' h hx) il ix t x
      | otherwise      = let r' = ins r
                             h' = hash2' (value l) (value r')
                         in Node h' il ix l r'
      where
        siz = ir - il + 1

----------------------------------------------------------------

fromList' :: (ByteArrayAccess inp, HashAlgorithm ha)
          => Settings inp ha -> [inp] -> HashTree inp ha
fromList' set [] = Empty $ hash0 set -- not used
fromList' set xs = ht
  where
    toLeaf = uncurry (leaf set)
    leaves = map toLeaf $ zip xs [0..]
    ht = buildup set leaves

leaf :: (ByteArrayAccess inp, HashAlgorithm ha)
     => Settings inp ha -> inp -> Index -> HashTree inp ha
leaf set x i = Leaf (hash1 set x) i x

link :: (ByteArrayAccess inp, HashAlgorithm ha)
     => Settings inp ha -> HashTree inp ha -> HashTree inp ha -> HashTree inp ha
link set l r = Node h (idxl l) (idxr r) l r
  where
    h = hash2 set (value l) (value r)

buildup :: (ByteArrayAccess inp, HashAlgorithm ha)
         => Settings inp ha -> [HashTree inp ha] -> HashTree inp ha
buildup _   [ht] = ht
buildup set hts  = buildup set (pairing set hts)

pairing :: (ByteArrayAccess inp, HashAlgorithm ha)
        => Settings inp ha -> [HashTree inp ha] -> [HashTree inp ha]
pairing set (t:u:vs) = link set t u : pairing set vs
pairing _       hts  = hts

----------------------------------------------------------------

data InclusionProof ha = InclusionProof !Int !Index ![Digest ha]
                       deriving (Eq, Show)

-- | Generating 'InclusionProof' for the target at the server side.
generateInclusionProof :: inp -> MerkleHashTrees inp ha -> Maybe (InclusionProof ha)
generateInclusionProof inp mht = case Map.lookup h (indices mht) of
    Nothing -> Nothing
    Just i  -> Just $ InclusionProof siz i (digests i)
  where
    h = hash1 (settings mht) inp
    ht = hashtree mht
    siz = idxr ht
    path m (Node _ _ _ l r)
      | m <= idxr l = value r : path m l
      | otherwise   = value l : path m r
    path _ _ = []
    digests i = reverse $ path i ht

-- | Verifying 'InclusionProof' at the client side.
verifyingInclusionProof :: (ByteArrayAccess inp, HashAlgorithm ha)
                        => Settings inp ha
                        -> inp               -- ^ The target
                        -> InclusionProof ha -- ^ InclusionProof of the target
                        -> Digest ha         -- ^ Merkle Tree Hash for the target size
                        -> Bool
verifyingInclusionProof set inp (InclusionProof siz idx dsts) rootMth = verify dsts dst0 idx0 == rootMth
  where
    dst0 = hash1 set inp
    idx0 = idx `shiftR` (width siz - length dsts)
    verify []     d0 _ = d0
    verify (d:ds) d0 i = verify ds d' (i `unsafeShiftR` 1)
      where
        d' = if testBit i 0 then hash2 set d d0
                            else hash2 set d0 d

----------------------------------------------------------------

width :: Int -> Int
width x = finiteBitSize x - countLeadingZeros x

isPowerOf2 :: Int -> Bool
isPowerOf2 n = (n .&. (n - 1)) == 0
