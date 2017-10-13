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
  , size
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

import Data.HashTree.Internal
