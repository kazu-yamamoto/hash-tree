module Data.HashTree where

import Data.Bits
import Data.List

data Tree a = Leaf a
            | Node (Tree a) (Tree a) deriving (Eq, Show)

singleton :: a -> Tree a
singleton = Leaf

join :: Tree a -> Tree a -> Tree a
join = Node

fromList :: [a] -> Tree a
fromList xs = reduce $ snd $ foldl' add (0,[]) $ map singleton xs
  where
    add (i,ts) t = (i+1, merge (mergeCount i) (t:ts))
    merge 0 ts        = ts
    merge n (t1:t2:ts) = merge (n - 1) (join t2 t1:ts)
    merge _ _ = error "merge"
    reduce [t] = t
    reduce (t1:t2:ts) = reduce (join t2 t1:ts)
    reduce _ = error "reduce"

mergeCount :: Int -> Int
mergeCount = countTrailingZeros . complement

log2Int :: Int -> Int
log2Int x = finiteBitSize x - 1 - countLeadingZeros x
