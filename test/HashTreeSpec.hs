module HashTreeSpec where

import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.HashTree
import Data.Maybe
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck

newtype Input = Input [ByteString] deriving Show -- non empty list

instance Arbitrary ByteString where
    arbitrary = BS.pack <$> listOf arbitrary -- Gen Word8

instance Arbitrary Input where
    arbitrary = Input . getNonEmpty <$> arbitrary -- Gen (NonEmptyList ByteString)

spec :: Spec
spec = do
    describe "verifyingInclusionProof" $ do
        prop "can be verified for a good target" $ \(Input bss@(b:_)) ->
            let set = defaultSettings
                ht = fromList set bss
                proof = fromJust $ generateInclusionProof b ht
            in verifyingInclusionProof set b proof (mth ht)
