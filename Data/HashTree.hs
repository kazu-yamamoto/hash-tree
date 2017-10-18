-- | Two-way (binary) Merkle Hash Trees which implements append-only logs and
--   provides both inclusion proof and consistency proof.
--   The API design is inspired by Certificate Transparency defined in RFC 6962.
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
  , InclusionProof
  , defaultInclusionProof
    -- ** Accessors
  , leafIndex
  , treeSize
  , inclusion
    -- ** Proof and verification
  , generateInclusionProof
  , verifyInclusionProof
    -- * Consistency Proof
  , ConsistencyProof
  , defaultConsistencyProof
    -- ** Accessors
  , firstTreeSize
  , secondTreeSize
  , consistency
    -- ** Proof and verification
  , generateConsistencyProof
  , verifyConsistencyProof
  ) where

import Data.HashTree.Internal
