-- | Two-way (binary) Merkle Hash Trees which implements append-only logs and
--   provides both inclusion proof and consistency proof.
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
    -- * Consistency Proof
  , ConsistencyProof
  , Index
  , generateConsistencyProof
  , verifyConsistencyProof
  ) where

import Data.HashTree.Internal
