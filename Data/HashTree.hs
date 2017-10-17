-- | Two-way (binary) Merkle Hash Trees which implements append-only logs and
--   provides both inclusion proof and consistency proof.
module Data.HashTree (
    -- * Settings
    Settings
  , defaultSettings
    -- ** Accessors
  , hash0
  , hash1
  , hash2
    -- * Merkle Hash Trees
  , MerkleHashTrees
    -- ** Accessors
  , info
  , size
  , digest
    -- ** Related types
  , TreeSize
  , Index
    -- ** Creating Merkle Hash Trees
  , empty
  , fromList
    -- ** Appending an element
  , add
    -- * Inclusion Proof
  , InclusionProof(..)
  , generateInclusionProof
  , verifyInclusionProof
    -- * Consistency Proof
  , ConsistencyProof(..)
  , generateConsistencyProof
  , verifyConsistencyProof
  ) where

import Data.HashTree.Internal
