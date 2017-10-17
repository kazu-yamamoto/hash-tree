{-# LANGUAGE OverloadedStrings #-}

module Data.HashTree.Internal (
    Settings(..)
  , defaultSettings
  , MerkleHashTrees(..)
  , digest
  , info
  , currentHead
  , empty
  , fromList
  , toHashTree
  , add
  , InclusionProof(..)
  , generateInclusionProof
  , verifyInclusionProof
  , ConsistencyProof(..)
  , Index
  , generateConsistencyProof
  , verifyConsistencyProof
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
import Data.IntMap.Strict (IntMap)
import qualified Data.IntMap.Strict as IntMap

-- $setup
-- >>> :set -XOverloadedStrings

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
    settings  :: !(Settings inp ha)
    -- | Getting the log size
  , size      :: !Int
    -- index is size of HashTree
    -- 0 for Empty
    -- 1 for Leaf 0 0
    -- 'size' for the last HashTree
  , hashtrees :: !(IntMap (HashTree inp ha))
  , indices   :: !(Map (Digest ha) Index)
  }

-- | Getting the Merkle Tree Hash.
digest :: Int -> MerkleHashTrees inp ha -> Maybe (Digest ha)
digest i mht = case IntMap.lookup i (hashtrees mht) of
    Nothing -> Nothing
    Just ht -> Just $ value ht

currentHead :: MerkleHashTrees inp ha -> Maybe (HashTree inp ha)
currentHead (MerkleHashTrees _ siz htdb _) = IntMap.lookup siz htdb

-- | Getting the root information of the Merkle Hash Tree.
--   A pair of the current size and the current Merle Tree Hash is returned.
info :: MerkleHashTrees inp ha -> (Int, Digest ha)
info mht = (siz, h)
  where
    siz = size mht
    Just h = digest siz mht

----------------------------------------------------------------

data HashTree inp ha =
    Empty !(Digest ha)
  | Leaf  !(Digest ha) !Index inp
  | Node  !(Digest ha) !Index !Index !(HashTree inp ha) !(HashTree inp ha)
  deriving (Eq, Show)

-- | Creating an empty 'MerkleHashTrees'.
empty :: Settings inp ha -> MerkleHashTrees inp ha
empty set = MerkleHashTrees {
    settings  = set
  , size      = 0
  , hashtrees = IntMap.insert 0 (Empty (hash0 set)) IntMap.empty
  , indices   = Map.empty
  }

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
add a mht@(MerkleHashTrees set siz htdb idb) =
    case Map.lookup hx idb of
        Just _  -> mht
        Nothing -> case IntMap.lookup siz htdb of
            Just ht -> let ht' = newht ht
                           htdb' = IntMap.insert siz' ht' htdb
                       in MerkleHashTrees set siz' htdb' idb'
            Nothing -> mht -- never reach
  where
    siz' = siz + 1
    hx = hash1 set a
    idb' = Map.insert hx siz idb

    newht ht = ins ht
      where
        ix = siz
        x = Leaf hx ix a

        hash2' = hash2 set
        ins (Empty _)           = x
        ins l@(Leaf hl il _ )   = Node (hash2' hl hx) il ix l x
        ins t@(Node h il ir l r)
          | isPowerOf2 sz = Node (hash2' h hx) il ix t x
          | otherwise     = let r' = ins r
                                h' = hash2' (value l) (value r')
                            in Node h' il ix l r'
          where
            sz = ir - il + 1

----------------------------------------------------------------

-- | A simple algorithm to create a binary balanced tree. O(n log n)
--   This is just for testing.
toHashTree :: (ByteArrayAccess inp, HashAlgorithm ha)
           => Settings inp ha -> [inp] -> HashTree inp ha
toHashTree set [] = Empty $ hash0 set -- not used
toHashTree set xs = ht
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
generateInclusionProof inp (MerkleHashTrees set siz htdb idb) = do
    ht <- IntMap.lookup siz htdb
    i <- Map.lookup h idb
    let digests = reverse $ path i ht
    return $ InclusionProof siz i digests
  where
    h = hash1 set inp
    path m (Node _ _ _ l r)
      | m <= idxr l = value r : path m l
      | otherwise   = value l : path m r
    path _ _ = []

-- | Verifying 'InclusionProof' at the client side.
--
-- >>> import Data.Maybe
-- >>> let mht = fromList defaultSettings ["0","1","2","3","4","5","6"]
-- >>> let target = "3"
-- >>> let proof = fromJust $ generateInclusionProof target mht
-- >>> let currentDigest = fromJust $ digest (size mht) mht
-- >>> verifyInclusionProof defaultSettings target proof currentDigest
-- True
verifyInclusionProof :: (ByteArrayAccess inp, HashAlgorithm ha)
                     => Settings inp ha
                     -> inp               -- ^ The target
                     -> InclusionProof ha -- ^ InclusionProof of the target
                     -> Digest ha         -- ^ Merkle Tree Hash for the target size
                     -> Bool
verifyInclusionProof set inp (InclusionProof siz idx dsts) rootMth = verify dsts dst0 idx0 == rootMth
  where
    dst0 = hash1 set inp
    idx0 = idx `shiftR` (width siz - length dsts)
    verify []     d0 _ = d0
    verify (d:ds) d0 i = verify ds d' (i `unsafeShiftR` 1)
      where
        d' = if testBit i 0 then hash2 set d d0
                            else hash2 set d0 d

----------------------------------------------------------------

data ConsistencyProof ha = ConsistencyProof !Index !Index ![Digest ha]
                         deriving (Eq, Show)

-- | Generating 'ConsistencyProof' for the target at the server side.
generateConsistencyProof :: Eq inp => Index -> Index -> MerkleHashTrees inp ha -> Maybe (ConsistencyProof ha)
generateConsistencyProof m n (MerkleHashTrees _ _ htdb _)
  | m < 0 || n < 0 = Nothing
  | m > n          = Nothing
  | m == 0         = do
      htn <- IntMap.lookup n htdb
      return $ ConsistencyProof m n [value htn]
  | otherwise = do
      htm <- IntMap.lookup m htdb
      htn <- IntMap.lookup n htdb
      let digests = prove htm htn True
      return $ ConsistencyProof m n digests
  where
    prove htm htn flag
      | htm == htn = if flag then [] else [value htm]
    prove htm@(Leaf _ _ _) (Node _ _ _ ln rn) flag
                   = prove htm ln flag ++ [value rn]
    prove htm@(Node _ midxl midxr lm rm) (Node _ nidxl nidxr ln rn) flag
      | sizm <= k  = prove htm ln flag ++ [value rn]
      | otherwise  = prove rm rn False ++ [value lm]
      where
        sizm = midxr - midxl + 1
        sizn = nidxr - nidxl + 1
        k = maxPowerOf2 (sizn - 1) -- e.g. if 8, take 4.
    prove _ _ _    = error "generateConsistencyProof:prove"

-- | Verifying 'ConsistencyProof' at the client side.
--
-- >>> import Data.Maybe
-- >>> let mht0 = fromList defaultSettings ["0","1","2","3"]
-- >>> let (m, digestM) = info mht0
-- >>> let mht1 = add "6" $ add "5" $ add "4" mht0
-- >>> let (n, digestN) = info mht1
-- >>> let proof = fromJust $ generateConsistencyProof m n mht1
-- >>> verifyConsistencyProof defaultSettings digestM digestN proof
-- True
verifyConsistencyProof :: (ByteArrayAccess inp, HashAlgorithm ha)
                       => Settings inp ha
                       -> Digest ha -- start
                       -> Digest ha -- end
                       -> ConsistencyProof ha
                       -> Bool
verifyConsistencyProof set firstHash secondHash (ConsistencyProof first second path)
  | first == 0      = case path of
      [c] -> secondHash == c
      _   -> False
  | first == second = null path && firstHash == secondHash
  | otherwise       = case path' of
      []   -> False
      c:cs -> verify (untilNotSet (first - 1, second - 1)) c c cs -- fixme:cs
  where
    path'
      | isPowerOf2 first = firstHash : path
      | otherwise        = path
    untilNotSet fsn@(fn,_)
      | fn `testBit` 0 = untilNotSet $ shiftR1 fsn
      | otherwise      = fsn
    untilSet fsn@(fn,_)
      | fn == 0        = fsn
      | fn `testBit` 0 = fsn
      | otherwise      = untilSet $ shiftR1 fsn
    shiftR1 (x,y) = (x `shiftR` 1, y `shiftR` 1)
    verify _     fr sr [] = fr == firstHash && sr == secondHash
    verify (_,0) _ _ _    = error "verifyConsistencyProof:verify"
    verify fsn@(fn,sn) fr sr (c:cs)
      | fn `testBit` 0 || fn == sn = let fr' = hash2 set c fr
                                         sr' = hash2 set c sr
                                         fsn'
                                          | not (fn `testBit` 0) = untilSet fsn
                                          | otherwise           = fsn
                                         fsn'' = shiftR1 fsn'
                                     in verify fsn'' fr' sr' cs
      | otherwise = let sr' = hash2 set sr c
                        fsn' = shiftR1 fsn
                    in verify fsn' fr sr' cs

----------------------------------------------------------------

width :: Int -> Int
width x = finiteBitSize x - countLeadingZeros x

isPowerOf2 :: Int -> Bool
isPowerOf2 n = (n .&. (n - 1)) == 0

maxPowerOf2 :: Int -> Int
maxPowerOf2 n = 2 ^ (width n - 1)
