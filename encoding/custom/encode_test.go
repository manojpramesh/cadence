package custom_test

import (
	"bytes"
	"fmt"
	"github.com/onflow/cadence/encoding/custom"
	"github.com/onflow/cadence/runtime/common"
	"github.com/onflow/cadence/runtime/sema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSemaCodecSimpleTypes(t *testing.T) {
	t.Parallel()

	type TestInfo struct {
		SimpleType *sema.SimpleType
		SubType    custom.EncodedSemaSimpleSubType
	}

	tests := []TestInfo{
		{sema.AnyType, custom.EncodedSemaSimpleSubTypeAnyType},
		{sema.AnyResourceType, custom.EncodedSemaSimpleSubTypeAnyResourceType},
		{sema.AnyStructType, custom.EncodedSemaSimpleSubTypeAnyStructType},
		{sema.BlockType, custom.EncodedSemaSimpleSubTypeBlockType},
		{sema.BoolType, custom.EncodedSemaSimpleSubTypeBoolType},
		{sema.CharacterType, custom.EncodedSemaSimpleSubTypeCharacterType},
		{sema.DeployedContractType, custom.EncodedSemaSimpleSubTypeDeployedContractType},
		{sema.InvalidType, custom.EncodedSemaSimpleSubTypeInvalidType},
		{sema.MetaType, custom.EncodedSemaSimpleSubTypeMetaType},
		{sema.NeverType, custom.EncodedSemaSimpleSubTypeNeverType},
		{sema.PathType, custom.EncodedSemaSimpleSubTypePathType},
		{sema.StoragePathType, custom.EncodedSemaSimpleSubTypeStoragePathType},
		{sema.CapabilityPathType, custom.EncodedSemaSimpleSubTypeCapabilityPathType},
		{sema.PublicPathType, custom.EncodedSemaSimpleSubTypePublicPathType},
		{sema.PrivatePathType, custom.EncodedSemaSimpleSubTypePrivatePathType},
		{sema.StorableType, custom.EncodedSemaSimpleSubTypeStorableType},
		{sema.StringType, custom.EncodedSemaSimpleSubTypeStringType},
		{sema.VoidType, custom.EncodedSemaSimpleSubTypeVoidType},
	}

	for _, typ := range tests {
		t.Run(typ.SimpleType.Name, func(t *testing.T) {
			testRootEncodeDecode(t, typ.SimpleType,
				byte(custom.EncodedSemaSimpleType),
				byte(typ.SubType),
			)
		})
	}
}

func TestSemaCodecNumericTypes(t *testing.T) {
	t.Parallel()

	type TestInfo struct {
		SimpleType sema.Type
		SubType    custom.EncodedSemaNumericSubType
	}

	tests := []TestInfo{
		{sema.NumberType, custom.EncodedSemaNumericSubTypeNumberType},
		{sema.SignedNumberType, custom.EncodedSemaNumericSubTypeSignedNumberType},
		{sema.IntegerType, custom.EncodedSemaNumericSubTypeIntegerType},
		{sema.SignedIntegerType, custom.EncodedSemaNumericSubTypeSignedIntegerType},
		{sema.IntType, custom.EncodedSemaNumericSubTypeIntType},
		{sema.Int8Type, custom.EncodedSemaNumericSubTypeInt8Type},
		{sema.Int16Type, custom.EncodedSemaNumericSubTypeInt16Type},
		{sema.Int32Type, custom.EncodedSemaNumericSubTypeInt32Type},
		{sema.Int64Type, custom.EncodedSemaNumericSubTypeInt64Type},
		{sema.Int128Type, custom.EncodedSemaNumericSubTypeInt128Type},
		{sema.Int256Type, custom.EncodedSemaNumericSubTypeInt256Type},
		{sema.UIntType, custom.EncodedSemaNumericSubTypeUIntType},
		{sema.UInt8Type, custom.EncodedSemaNumericSubTypeUInt8Type},
		{sema.UInt16Type, custom.EncodedSemaNumericSubTypeUInt16Type},
		{sema.UInt32Type, custom.EncodedSemaNumericSubTypeUInt32Type},
		{sema.UInt64Type, custom.EncodedSemaNumericSubTypeUInt64Type},
		{sema.UInt128Type, custom.EncodedSemaNumericSubTypeUInt128Type},
		{sema.UInt256Type, custom.EncodedSemaNumericSubTypeUInt256Type},
		{sema.Word8Type, custom.EncodedSemaNumericSubTypeWord8Type},
		{sema.Word16Type, custom.EncodedSemaNumericSubTypeWord16Type},
		{sema.Word32Type, custom.EncodedSemaNumericSubTypeWord32Type},
		{sema.Word64Type, custom.EncodedSemaNumericSubTypeWord64Type},
		{sema.FixedPointType, custom.EncodedSemaNumericSubTypeFixedPointType},
		{sema.SignedFixedPointType, custom.EncodedSemaNumericSubTypeSignedFixedPointType},
	}

	for _, typ := range tests {
		t.Run(typ.SimpleType.String(), func(t *testing.T) {
			t.Parallel()
			testRootEncodeDecode(t, typ.SimpleType,
				byte(custom.EncodedSemaNumericType),
				byte(typ.SubType),
			)
		})
	}
}

// TODO more misc types
func TestSemaCodecMiscTypes(t *testing.T) {
	t.Run("AddressType", func(t *testing.T) {
		t.Parallel()
		testRootEncodeDecode(t, &sema.AddressType{}, byte(custom.EncodedSemaAddressType))
	})
}

func TestSemaCodecMiscValues(t *testing.T) {
	t.Parallel()

	t.Run("length", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		length := 10
		testEncodeDecode(
			t,
			length,
			buffer,
			encoder.EncodeLength,
			decoder.DecodeLength,
			[]byte{0, 0, 0, byte(length)},
		)
	})

	t.Run("address", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		addressBytes := []byte{0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00}
		address := common.MustBytesToAddress(addressBytes)

		testEncodeDecode(
			t,
			address,
			buffer,
			encoder.EncodeAddress,
			decoder.DecodeAddress,
			addressBytes,
		)
	})

	t.Run("string", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		s := "some string \x00 foo \t \n\r\n $ 5"

		testEncodeDecode(
			t,
			s,
			buffer,
			encoder.EncodeString,
			decoder.DecodeString,
			append(
				[]byte{0, 0, 0, byte(len(s))},
				[]byte(s)...,
			),
		)
	})
}

func TestSemaCodecLocations(t *testing.T) {
	t.Parallel()

	for _, prefix := range []string{
		common.AddressLocationPrefix,
		common.IdentifierLocationPrefix,
		common.ScriptLocationPrefix,
		common.StringLocationPrefix,
		common.TransactionLocationPrefix,
		common.REPLLocationPrefix,
		custom.NilLocationPrefix,
	} {
		t.Run(fmt.Sprintf("prefix: %s", prefix), func(t *testing.T) {
			t.Parallel()

			encoder, decoder, buffer := NewTestCodec()

			testEncodeDecode(
				t,
				custom.NilLocationPrefix,
				buffer,
				encoder.EncodeLocationPrefix,
				decoder.DecodeLocationPrefix,
				[]byte{prefix[0]},
			)
		})
	}

	t.Run("EncodeLocation(nil)", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		testEncodeDecode[common.Location](
			t,
			nil,
			buffer,
			encoder.EncodeLocation,
			decoder.DecodeLocation,
			[]byte{custom.NilLocationPrefix[0]},
		)
	})

	t.Run("EncodeLocation(Address)", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		address := common.AddressLocation{
			Address: common.Address{12, 13, 14},
			Name:    "foo-bar",
		}
		testEncodeDecode[common.Location](
			t,
			address,
			buffer,
			encoder.EncodeLocation,
			decoder.DecodeLocation,
			Concat(
				[]byte{common.AddressLocationPrefix[0]},
				address.Address.Bytes(),
				[]byte{0, 0, 0, byte(len(address.Name))},
				[]byte(address.Name),
			),
		)
	})

	t.Run("EncodeLocation(Identifier)", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		identifier := common.IdentifierLocation("id \x01 \x00\n\rsomeid\n")
		testEncodeDecode[common.Location](
			t,
			identifier,
			buffer,
			encoder.EncodeLocation,
			decoder.DecodeLocation,
			Concat(
				[]byte{common.IdentifierLocationPrefix[0]},
				[]byte{0, 0, 0, byte(len(identifier))},
				[]byte(identifier),
			),
		)
	})

	t.Run("EncodeLocation(Script)", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		script := common.ScriptLocation("id \x01 \x00\n\rsomeid\n")
		testEncodeDecode[common.Location](
			t,
			script,
			buffer,
			encoder.EncodeLocation,
			decoder.DecodeLocation,
			Concat(
				[]byte{common.ScriptLocationPrefix[0]},
				[]byte{0, 0, 0, byte(len(script))},
				script,
			),
		)
	})

	t.Run("EncodeLocation(String)", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		s := common.StringLocation("id \x01 \x00\n\rsomeid\n")
		testEncodeDecode[common.Location](
			t,
			s,
			buffer,
			encoder.EncodeLocation,
			decoder.DecodeLocation,
			Concat(
				[]byte{common.StringLocationPrefix[0]},
				[]byte{0, 0, 0, byte(len(s))},
				[]byte(s),
			),
		)
	})

	t.Run("EncodeLocation(Transaction)", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		s := common.TransactionLocation("id \x01 \x00\n\rsomeid\n")
		testEncodeDecode[common.Location](
			t,
			s,
			buffer,
			encoder.EncodeLocation,
			decoder.DecodeLocation,
			Concat(
				[]byte{common.TransactionLocationPrefix[0]},
				[]byte{0, 0, 0, byte(len(s))},
				s,
			),
		)
	})

	t.Run("EncodeLocation(REPL)", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		s := common.REPLLocation{}
		testEncodeDecode[common.Location](
			t,
			s,
			buffer,
			encoder.EncodeLocation,
			decoder.DecodeLocation,
			[]byte{common.REPLLocationPrefix[0]},
		)
	})
}

func TestSemaCodecCompositeType(t *testing.T) {
	t.Parallel()

	theCompositeType := sema.AccountKeyType

	encoder, buffer := NewTestEncoder()
	err := encoder.Encode(theCompositeType)
	require.NoError(t, err, "encoding error")

	// verify the first few encoded bytes
	expected := []byte{
		// type of encoded sema type
		byte(custom.EncodedSemaCompositeType),

		// location
		custom.NilLocationPrefix[0],

		// length of identifier
		0, 0, 0,
		byte(len(sema.AccountKeyTypeName)),

		// identifier
		sema.AccountKeyTypeName[0],
		sema.AccountKeyTypeName[1],
		sema.AccountKeyTypeName[2],
		sema.AccountKeyTypeName[3],
		sema.AccountKeyTypeName[4],
		sema.AccountKeyTypeName[5],
		sema.AccountKeyTypeName[6],
		sema.AccountKeyTypeName[7],
		sema.AccountKeyTypeName[8],
		sema.AccountKeyTypeName[9],

		// composite kind
		0, 0, 0, 0, 0, 0, 0,
		byte(common.CompositeKindStructure),

		// ExplicitInterfaceConformances array is nil
		byte(custom.EncodedBoolTrue),

		// ImplicitTypeRequirementConformances array is nil
		byte(custom.EncodedBoolTrue),
	}
	assert.Equal(t, expected, buffer.Bytes()[:len(expected)], "encoded bytes")

	decoder := custom.NewSemaDecoder(nil, buffer)
	output, err := decoder.Decode()
	require.NoError(t, err)

	// populates `cachedIdentifiers` for top-level and its members
	output.QualifiedString()
	switch c := output.(type) {
	case *sema.CompositeType:
		c.Members.Foreach(func(key string, value *sema.Member) {
			value.TypeAnnotation.QualifiedString()
		})
	}

	// verify Equal(...) method equality... basically a smoke test
	assert.True(t, output.Equal(theCompositeType), ".Equal(...) is false")

	switch c := output.(type) {
	case *sema.CompositeType:
		// verify the easily verified
		assert.Equal(t, theCompositeType.Fields, c.Fields)
		assert.Equal(t, theCompositeType.Kind, c.Kind)
		assert.Equal(t, theCompositeType.Location, c.Location)
		assert.Equal(t, theCompositeType.EnumRawType, c.EnumRawType)
		assert.Equal(t, theCompositeType.Identifier, c.Identifier)
		assert.Equal(t, theCompositeType.ImportableWithoutLocation, c.ImportableWithoutLocation)
		assert.Equal(t, theCompositeType.ConstructorParameters, c.ConstructorParameters)
		assert.Equal(t, theCompositeType.ExplicitInterfaceConformances, c.ExplicitInterfaceConformances)
		assert.Equal(t, theCompositeType.ImplicitTypeRequirementConformances, c.ImplicitTypeRequirementConformances)
		assert.Equal(t, theCompositeType.GetContainerType(), c.GetContainerType())
		assert.Equal(t, theCompositeType.GetNestedTypes(), c.GetNestedTypes())

		// verify member equality
		require.Equal(t, theCompositeType.Members.Len(), c.Members.Len(), "members length")
		c.Members.Foreach(func(key string, actual *sema.Member) {
			expected, present := theCompositeType.Members.Get(key)
			require.True(t, present, "extra member: %s", key)

			assert.Equal(t, expected.ContainerType.ID(), actual.ContainerType.ID(), "container type for %s", key)
			assert.Equal(t, expected.TypeAnnotation.QualifiedString(), actual.TypeAnnotation.QualifiedString(), "type annotation for %s", key)
		})
	default:
		require.Fail(t, "decoded type is not CompositeType")
	}
}

//
// Helpers
//

func testRootEncodeDecode(
	t *testing.T,
	input sema.Type,
	expectedEncoding ...byte,
) ([]byte, sema.Type) {
	blob, err := custom.EncodeSema(input)
	require.NoError(t, err, "encoding error")

	if expectedEncoding != nil {
		assert.Equal(t, expectedEncoding, blob)
	}

	output, err := custom.DecodeSema(nil, blob)
	require.NoError(t, err, "decoding error")

	assert.Equal(t, input, output, "decoded message differs from input")

	return blob, output
}

func testEncodeDecode[T any](
	t *testing.T,
	input T,
	buffer *bytes.Buffer,
	encode func(T) error,
	decode func() (T, error),
	expectedEncoding []byte,
) {
	err := encode(input)
	require.NoError(t, err)

	if expectedEncoding != nil {
		assert.Equal(t, expectedEncoding, buffer.Bytes(), "encoding error")
	}

	output, err := decode()
	require.NoError(t, err)

	assert.Equal(t, input, output, "decoding error")
}

func NewTestEncoder() (*custom.SemaEncoder, *bytes.Buffer) {
	var w bytes.Buffer
	encoder := custom.NewSemaEncoder(&w)
	return encoder, &w
}

func NewTestCodec() (encoder *custom.SemaEncoder, decoder *custom.SemaDecoder, buffer *bytes.Buffer) {
	var w bytes.Buffer
	buffer = &w
	encoder = custom.NewSemaEncoder(buffer)
	decoder = custom.NewSemaDecoder(nil, buffer)
	return
}

func Concat(deep ...[]byte) []byte {
	length := 0
	for _, b := range deep {
		length += len(b)
	}

	flat := make([]byte, 0, length)
	for _, b := range deep {
		flat = append(flat, b...)
	}

	return flat
}
