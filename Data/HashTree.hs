module Data.HashTree (
    Tree
  , singleton
  , link
  , fromList
  ) where

-- import Data.Bits

data Tree a = Leaf a
            | Node (Tree a) (Tree a) deriving (Eq, Show)

singleton :: a -> Tree a
singleton = Leaf

link :: Tree a -> Tree a -> Tree a
link = Node

-- |
--
-- >>> fromList [0..6 :: Int]
-- Node (Node (Node (Leaf 0) (Leaf 1)) (Node (Leaf 2) (Leaf 3))) (Node (Node (Leaf 4) (Leaf 5)) (Leaf 6))
fromList :: [a] -> Tree a
fromList [] = error "No Element"
fromList xs = buildup (map singleton xs)

buildup :: [Tree a] -> Tree a
buildup [t] = t
buildup ts  = buildup (pairing ts)

pairing :: [Tree a] -> [Tree a]
pairing (t:u:vs) = link t u : pairing vs
pairing ts       = ts

----------------------------------------------------------------
{-
mergeCount :: Int -> Int
mergeCount = countTrailingZeros . complement

log2Int :: Int -> Int
log2Int x = finiteBitSize x - 1 - countLeadingZeros x
-}
