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
    describe "info" $ do
        prop "The root hash of 1-size tree is equal to the leaf hash" $ \bs ->
            let mht = add (bs :: ByteString) $ empty set
                h1 = snd $ info mht
                h2 = hash1 set bs
            in h1 == h2
    describe "fromList" $ do
        prop "creates a perfectly branched tree" $ \(Input bss) ->
            let Just ht = currentHead $ fromList set bss
                ht' = toHashTree set $ nub bss
            in ht == ht'
    describe "verifyInclusionProof" $ do
        prop "can be verified for a good target" $ \(Input bss@(b:_)) ->
            let mht = fromList set bss
                proof = fromJust $ generateInclusionProof b mht
                Just h = digest (size mht) mht
            in verifyInclusionProof set b proof h
    describe "verifyConsistencyProof" $ do
        prop "can be verified" $ \(Input bss) m0 n0 ->
            let mht = fromList set bss
                siz = size mht
                aj x b
                  | x < 0     = negate x `mod` b
                  | otherwise = x `mod` b
                m0' = aj m0 siz
                n0' = aj n0 siz
                (m,n) = if m0' <= n0' then (m0',n0') else (n0',m0')
                proof = fromJust $ generateConsistencyProof m n mht
                Just dm = digest m mht
                Just dn = digest n mht
            in verifyConsistencyProof set dm dn proof
