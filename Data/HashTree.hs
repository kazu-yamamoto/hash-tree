{-# LANGUAGE OverloadedStrings #-}

-- | Two-way (binary) Merkle Hash Trees
module Data.HashTree (
    -- * Settings
    Settings
  , defaultSettings
    -- ** Settings accessors
  , hash0
  , hash1
  , hash2
    -- * Merkle Hash Trees
  , HashTree
  , mth
  , size
    -- ** Creating Merkle Hash Trees
  , emptyHashTree
  , fromList
    -- ** Appending an element
  , add
    -- * Inclusion Proof
  , InclusionProof
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
data HashTree inp ha = HashTree {
    settings :: !(Settings inp ha)
  , hashtree :: !(MHT inp ha)
  , indices  :: !(Map (Digest ha) Index)
  }

data MHT inp ha =
    Empty !(Digest ha)
  | Leaf  !(Digest ha) !Index inp
  | Node  !(Digest ha) !Index !Index !(MHT inp ha) !(MHT inp ha)
  deriving (Eq, Show)

-- | Creating an empty 'HashTree'.
emptyHashTree :: Settings inp ha -> HashTree inp ha
emptyHashTree set = HashTree set (Empty (hash0 set)) Map.empty

-- | Getting the size
size :: HashTree inp ha -> Int
size = size' . hashtree

size' :: MHT inp ha -> Int
size' (Empty _) = 0
size' t         = idxr t + 1

-- | Getting the Merkle Tree Hash.
mth :: HashTree inp ha -> Digest ha
mth = mth' . hashtree

mth' :: MHT inp ha -> Digest ha
mth' (Empty ha)         = ha
mth' (Leaf  ha _ _)     = ha
mth' (Node  ha _ _ _ _) = ha

{-
idxl :: MHT t1 t -> Index
idxl (Leaf _ i _)     = i
idxl (Node _ i _ _ _) = i
idxl _                = error "idxl"
-}

idxr :: MHT t1 t -> Index
idxr (Leaf _ i _)     = i
idxr (Node _ _ i _ _) = i
idxr (Empty _)        = error "idxr"

-- | Creating a Merkle Hash Tree from a list of elements. O(n log n)
fromList :: (ByteArrayAccess inp, HashAlgorithm ha)
         => Settings inp ha -> [inp] -> HashTree inp ha
fromList set xs = foldl' (flip add) (emptyHashTree set) xs

-- | Adding (appending) an element. O(log n)
add :: (ByteArrayAccess inp, HashAlgorithm ha)
     => inp -> HashTree inp ha -> HashTree inp ha
add a ht@(HashTree set mht idb) = case Map.lookup hx idb of
    Just _  -> ht
    Nothing -> HashTree set mht' idb'
  where
    idb' = Map.insert hx ix idb

    hx = hash1 set a
    ix = size' mht
    x = Leaf hx ix a

    mht' = ins mht
    hash2' = hash2 set
    ins (Empty _)           = x
    ins l@(Leaf hl il _ )   = Node (hash2' hl hx) il ix l x
    ins t@(Node h il ir l r)
      | isPowerOf2 siz = Node (hash2' h hx) il ix t x
      | otherwise      = let r' = ins r
                             h' = hash2' (mth' l) (mth' r')
                         in Node h' il ix l r'
      where
        siz = ir - il + 1

----------------------------------------------------------------

data InclusionProof ha = InclusionProof !Int !Index ![Digest ha]
                       deriving (Eq, Show)

-- | Generating 'InclusionProof' for the target at the server side.
generateInclusionProof :: inp -> HashTree inp ha -> Maybe (InclusionProof ha)
generateInclusionProof inp ht = case Map.lookup h (indices ht) of
    Nothing -> Nothing
    Just i  -> Just $ InclusionProof siz i (digests i)
  where
    h = hash1 (settings ht) inp
    mht = hashtree ht
    siz = idxr mht
    path m (Node _ _ _ l r)
      | m <= idxr l = mth' r : path m l
      | otherwise   = mth' l : path m r
    path _ _ = []
    digests i = reverse $ path i mht

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

width :: Int -> Int
width x = finiteBitSize x - countLeadingZeros x

isPowerOf2 :: Int -> Bool
isPowerOf2 n = (n .&. (n - 1)) == 0
