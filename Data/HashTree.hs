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
  , fromList
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

-- | The data type for Merkle Hash Trees.
--   The first parameter is input data type.
--   The second one is digest data type.
data HashTree inp ha =
    Leaf !Int !(Digest ha) inp
  | Node !Int Int !(Digest ha) !(HashTree inp ha) !(HashTree inp ha)
  deriving (Eq, Show)

singleton :: (ByteArrayAccess inp, HashAlgorithm ha)
          => Settings inp ha -> inp -> Int -> HashTree inp ha
singleton settings x i = Leaf i (hash1 settings x) x

mth :: HashTree inp ha -> Digest ha
mth (Leaf _ ha _)     = ha
mth (Node _ _ ha _ _) = ha

link :: (ByteArrayAccess inp, HashAlgorithm ha)
     => Settings inp ha -> HashTree inp ha -> HashTree inp ha -> HashTree inp ha
link settings l r = Node (idxl l) (idxr r) h l r
  where
    h = hash2 settings (mth l) (mth r)

idxl :: HashTree t1 t -> Int
idxl (Leaf i _ _) = i
idxl (Node i _ _ _ _) = i

idxr :: HashTree t1 t -> Int
idxr (Leaf i _ _) = i
idxr (Node _ i _ _ _) = i

-- | Creating a Merkle Hash Tree from a list of elements.
fromList :: (ByteArrayAccess inp, HashAlgorithm ha)
         => Settings inp ha -> [inp] -> HashTree inp ha
fromList _ [] = error "No Element"
fromList settings xs = buildup settings $ map leaf $ zip xs [0..]
  where
    leaf = uncurry (singleton settings)

buildup :: (ByteArrayAccess inp, HashAlgorithm ha)
         => Settings inp ha -> [HashTree inp ha] -> HashTree inp ha
buildup _        [t] = t
buildup settings ts  = buildup settings (pairing settings ts)

pairing :: (ByteArrayAccess inp, HashAlgorithm ha)
         => Settings inp ha -> [HashTree inp ha] -> [HashTree inp ha]
pairing settings (t:u:vs) = link settings t u : pairing settings vs
pairing _        ts       = ts

----------------------------------------------------------------

generateInclusionProof :: Int -> HashTree inp ha -> [Digest ha]
generateInclusionProof i t = reverse $ path i t
  where
    path m (Node _ _ _ l r)
      | m <= idxr l = mth r : path m l
      | otherwise   = mth l : path m r
    path _ _ = []

verifyingInclusionProof :: (ByteArrayAccess inp, HashAlgorithm ha)
                        => Settings inp ha -> inp -> Int -> [Digest ha] -> HashTree inp ha -> Bool
verifyingInclusionProof settings inp idx dsts t = proof dsts dst0 idx0 == mth t
  where
    dst0 = hash1 settings inp
    idx0 = idx `shiftR` (width (idxr t) - length dsts)
    proof []     d0 _ = d0
    proof (d:ds) d0 i = proof ds d' (i `unsafeShiftR` 1)
      where
        d' = if testBit i 0 then hash2 settings d d0
                            else hash2 settings d0 d

----------------------------------------------------------------
{-
mergeCount :: Int -> Int
mergeCount = countTrailingZeros . complement

log2Int :: Int -> Int
log2Int x = finiteBitSize x - 1 - countLeadingZeros x
-}

width :: Int -> Int
width x = finiteBitSize x - countLeadingZeros x
