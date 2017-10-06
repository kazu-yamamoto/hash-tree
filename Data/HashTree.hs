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

import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as BA
import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Char8 ()
import Data.Bits
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

leaf :: (ByteArrayAccess inp, HashAlgorithm ha)
     => Settings inp ha -> inp -> Index -> MHT inp ha
leaf set x i = Leaf (hash1 set x) i x

-- | Getting a Merkle Tree Hash.
mth :: HashTree inp ha -> Digest ha
mth = mth' . hashtree

mth' :: MHT inp ha -> Digest ha
mth' (Empty ha)         = ha
mth' (Leaf  ha _ _)     = ha
mth' (Node  ha _ _ _ _) = ha

link :: (ByteArrayAccess inp, HashAlgorithm ha)
     => Settings inp ha -> MHT inp ha -> MHT inp ha -> MHT inp ha
link set l r = Node h (idxl l) (idxr r) l r
  where
    h = hash2 set (mth' l) (mth' r)

idxl :: MHT t1 t -> Index
idxl (Leaf _ i _)     = i
idxl (Node _ i _ _ _) = i
idxl _                = error "idxl"

idxr :: MHT t1 t -> Index
idxr (Leaf _ i _)     = i
idxr (Node _ _ i _ _) = i
idxr _                = error "idxr"

-- | Creating a Merkle Hash Tree from a list of elements.
fromList :: (ByteArrayAccess inp, HashAlgorithm ha)
         => Settings inp ha -> [inp] -> HashTree inp ha
fromList set [] = emptyHashTree set
fromList set xs = HashTree set mht hm
  where
    toLeaf = uncurry (leaf set)
    leaves = map toLeaf $ zip xs [0..]
    mht = buildup set leaves
    kvs = map (\(Leaf h i _) -> (h,i)) leaves
    hm = Map.fromList kvs

buildup :: (ByteArrayAccess inp, HashAlgorithm ha)
         => Settings inp ha -> [MHT inp ha] -> MHT inp ha
buildup _   [t] = t
buildup set ts  = buildup set (pairing set ts)

pairing :: (ByteArrayAccess inp, HashAlgorithm ha)
        => Settings inp ha -> [MHT inp ha] -> [MHT inp ha]
pairing set (t:u:vs) = link set t u : pairing set vs
pairing _        ts  = ts

-- | Adding (appending) an element.
add :: (ByteArrayAccess inp, HashAlgorithm ha)
     => inp -> HashTree inp ha -> HashTree inp ha
add = undefined

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

----------------------------------------------------------------
{-
mergeCount :: Int -> Int
mergeCount = countTrailingZeros . complement

log2Int :: Int -> Int
log2Int x = finiteBitSize x - 1 - countLeadingZeros x
-}

width :: Int -> Int
width x = finiteBitSize x - countLeadingZeros x
