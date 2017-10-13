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
  , MerkleHashTrees
  , size
  , digest
    -- ** Creating Merkle Hash Trees
  , empty
  , fromList
    -- ** Appending an element
  , add
    -- * Inclusion Proof
  , InclusionProof
  , generateInclusionProof
  , verifyInclusionProof
  ) where

import Data.HashTree.Internal
