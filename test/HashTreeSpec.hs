{-# OPTIONS_GHC -fno-warn-orphans #-}

module HashTreeSpec where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.HashTree.Internal
import Data.Maybe
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Data.List (nub)

newtype Input = Input [ByteString] deriving Show -- non empty list

instance Arbitrary ByteString where
    arbitrary = BS.pack <$> listOf arbitrary -- Gen Word8

instance Arbitrary Input where
    arbitrary = Input . getNonEmpty <$> arbitrary -- Gen (NonEmptyList ByteString)

spec :: Spec
spec = do
    let set = defaultSettings
    describe "fromList" $ do
        prop "creates a perfectly branched tree" $ \(Input bss) ->
            let bss' = nub bss
                Just ht = currentHead $ fromList set bss'
                ht' = fromList' set bss'
            in ht == ht'
    describe "verifyInclusionProof" $ do
        prop "can be verified for a good target" $ \(Input bss@(b:_)) ->
            let mht = fromList set bss
                proof = fromJust $ generateInclusionProof b mht
                Just h = digest (size mht) mht
            in verifyInclusionProof set b proof h
