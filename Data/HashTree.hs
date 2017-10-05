{-# LANGUAGE OverloadedStrings #-}

module Data.HashTree (
    MerkleTreeHash
  , Settings(..)
  , defaultSettings
  , HashTree
  , fromList
  ) where

import Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as BA
import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Char8 ()
-- import Data.Bits

newtype MerkleTreeHash a = MerkleTreeHash (Digest a) deriving (Eq, Show)

instance ByteArrayAccess (MerkleTreeHash a) where
  length (MerkleTreeHash dst) = BA.length dst
  withByteArray (MerkleTreeHash dst) = BA.withByteArray dst

data Settings inp ha = Settings {
    hash0 :: MerkleTreeHash ha
  , hash1 :: inp -> MerkleTreeHash ha
  , hash2 :: MerkleTreeHash ha -> MerkleTreeHash ha -> MerkleTreeHash ha
  }

sha256 :: ByteString -> Digest SHA256
sha256 = hash

defaultSettings :: Settings ByteString SHA256
defaultSettings = Settings {
    hash0 =  MerkleTreeHash $ sha256 ""
  , hash1 = \x -> MerkleTreeHash $ sha256 (BS.singleton 0x00 `BS.append` x)
  , hash2 = \x y ->  MerkleTreeHash $ sha256 $ BS.concat [BS.singleton 0x01, BA.convert x, BA.convert y]
  }

data HashTree inp ha =
    Leaf !Int !(MerkleTreeHash ha) inp
  | Node !Int Int !(MerkleTreeHash ha) !(HashTree inp ha) !(HashTree inp ha)
  deriving (Eq, Show)

singleton :: (ByteArrayAccess inp, HashAlgorithm ha)
          => Settings inp ha -> inp -> Int -> HashTree inp ha
singleton settings x i = Leaf i (hash1 settings x) x

mth :: HashTree inp ha -> MerkleTreeHash ha
mth (Leaf _ ha _)     = ha
mth (Node _ _ ha _ _) = ha

link :: (ByteArrayAccess inp, HashAlgorithm ha)
     => Settings inp ha -> HashTree inp ha -> HashTree inp ha -> HashTree inp ha
link settings l r = Node (idxl l) (idxr r) h l r
  where
    h = hash2 settings (mth l) (mth r)
    idxl (Leaf i _ _) = i
    idxl (Node i _ _ _ _) = i
    idxr (Leaf i _ _) = i
    idxr (Node _ i _ _ _) = i

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
{-
mergeCount :: Int -> Int
mergeCount = countTrailingZeros . complement

log2Int :: Int -> Int
log2Int x = finiteBitSize x - 1 - countLeadingZeros x
-}
