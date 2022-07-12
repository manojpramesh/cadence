package sema_codec_test

import (
	"bytes"
	"fmt"
	"github.com/onflow/cadence/encoding/custom/sema_codec"
	"github.com/onflow/cadence/runtime/ast"
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
		Type       sema_codec.EncodedSema
	}

	tests := []TestInfo{
		{sema.AnyType, sema_codec.EncodedSemaSimpleTypeAnyType},
		{sema.AnyResourceType, sema_codec.EncodedSemaSimpleTypeAnyResourceType},
		{sema.AnyStructType, sema_codec.EncodedSemaSimpleTypeAnyStructType},
		{sema.BlockType, sema_codec.EncodedSemaSimpleTypeBlockType},
		{sema.BoolType, sema_codec.EncodedSemaSimpleTypeBoolType},
		{sema.CharacterType, sema_codec.EncodedSemaSimpleTypeCharacterType},
		{sema.DeployedContractType, sema_codec.EncodedSemaSimpleTypeDeployedContractType},
		{sema.InvalidType, sema_codec.EncodedSemaSimpleTypeInvalidType},
		{sema.MetaType, sema_codec.EncodedSemaSimpleTypeMetaType},
		{sema.NeverType, sema_codec.EncodedSemaSimpleTypeNeverType},
		{sema.PathType, sema_codec.EncodedSemaSimpleTypePathType},
		{sema.StoragePathType, sema_codec.EncodedSemaSimpleTypeStoragePathType},
		{sema.CapabilityPathType, sema_codec.EncodedSemaSimpleTypeCapabilityPathType},
		{sema.PublicPathType, sema_codec.EncodedSemaSimpleTypePublicPathType},
		{sema.PrivatePathType, sema_codec.EncodedSemaSimpleTypePrivatePathType},
		{sema.StorableType, sema_codec.EncodedSemaSimpleTypeStorableType},
		{sema.StringType, sema_codec.EncodedSemaSimpleTypeStringType},
		{sema.VoidType, sema_codec.EncodedSemaSimpleTypeVoidType},
	}

	for _, typ := range tests {
		t.Run(typ.SimpleType.Name, func(t *testing.T) {
			testRootEncodeDecode(t, typ.SimpleType,
				byte(typ.Type),
			)
		})
	}
}

func TestSemaCodecNumericTypes(t *testing.T) {
	t.Parallel()

	type TestInfo struct {
		SimpleType sema.Type
		Type       sema_codec.EncodedSema
	}

	tests := []TestInfo{
		{sema.NumberType, sema_codec.EncodedSemaNumericTypeNumberType},
		{sema.SignedNumberType, sema_codec.EncodedSemaNumericTypeSignedNumberType},
		{sema.IntegerType, sema_codec.EncodedSemaNumericTypeIntegerType},
		{sema.SignedIntegerType, sema_codec.EncodedSemaNumericTypeSignedIntegerType},
		{sema.IntType, sema_codec.EncodedSemaNumericTypeIntType},
		{sema.Int8Type, sema_codec.EncodedSemaNumericTypeInt8Type},
		{sema.Int16Type, sema_codec.EncodedSemaNumericTypeInt16Type},
		{sema.Int32Type, sema_codec.EncodedSemaNumericTypeInt32Type},
		{sema.Int64Type, sema_codec.EncodedSemaNumericTypeInt64Type},
		{sema.Int128Type, sema_codec.EncodedSemaNumericTypeInt128Type},
		{sema.Int256Type, sema_codec.EncodedSemaNumericTypeInt256Type},
		{sema.UIntType, sema_codec.EncodedSemaNumericTypeUIntType},
		{sema.UInt8Type, sema_codec.EncodedSemaNumericTypeUInt8Type},
		{sema.UInt16Type, sema_codec.EncodedSemaNumericTypeUInt16Type},
		{sema.UInt32Type, sema_codec.EncodedSemaNumericTypeUInt32Type},
		{sema.UInt64Type, sema_codec.EncodedSemaNumericTypeUInt64Type},
		{sema.UInt128Type, sema_codec.EncodedSemaNumericTypeUInt128Type},
		{sema.UInt256Type, sema_codec.EncodedSemaNumericTypeUInt256Type},
		{sema.Word8Type, sema_codec.EncodedSemaNumericTypeWord8Type},
		{sema.Word16Type, sema_codec.EncodedSemaNumericTypeWord16Type},
		{sema.Word32Type, sema_codec.EncodedSemaNumericTypeWord32Type},
		{sema.Word64Type, sema_codec.EncodedSemaNumericTypeWord64Type},
		{sema.FixedPointType, sema_codec.EncodedSemaNumericTypeFixedPointType},
		{sema.SignedFixedPointType, sema_codec.EncodedSemaNumericTypeSignedFixedPointType},
	}

	for _, typ := range tests {
		t.Run(typ.SimpleType.String(), func(t *testing.T) {
			t.Parallel()
			testRootEncodeDecode(t, typ.SimpleType,
				byte(typ.Type),
			)
		})
	}
}

func TestSemaCodecMiscTypes(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		testRootEncodeDecode(t, nil, byte(sema_codec.EncodedSemaNilType))
	})

	t.Run("AddressType", func(t *testing.T) {
		t.Parallel()
		testRootEncodeDecode(t, &sema.AddressType{}, byte(sema_codec.EncodedSemaAddressType))
	})

	t.Run("OptionalType", func(t *testing.T) {
		t.Parallel()

		testRootEncodeDecode(
			t,
			&sema.OptionalType{Type: sema.BoolType},
			byte(sema_codec.EncodedSemaOptionalType),
			byte(sema_codec.EncodedSemaSimpleTypeBoolType),
		)
	})

	t.Run("ReferenceType", func(t *testing.T) {
		t.Parallel()

		testRootEncodeDecode(
			t,
			&sema.ReferenceType{
				Authorized: false,
				Type:       sema.AnyType,
			},
			byte(sema_codec.EncodedSemaReferenceType),
			byte(sema_codec.EncodedBoolFalse),
			byte(sema_codec.EncodedSemaSimpleTypeAnyType),
		)
	})

	t.Run("CapabilityType", func(t *testing.T) {
		t.Parallel()

		testRootEncodeDecode(
			t,
			&sema.CapabilityType{BorrowType: sema.VoidType},
			byte(sema_codec.EncodedSemaCapabilityType),
			byte(sema_codec.EncodedSemaSimpleTypeVoidType),
		)
	})

	t.Run("GenericType", func(t *testing.T) {
		t.Parallel()

		name := "could be anything"

		testRootEncodeDecode(
			t,
			&sema.GenericType{TypeParameter: &sema.TypeParameter{
				Name:      name,
				TypeBound: sema.Int32Type,
				Optional:  true,
			}},
			Concat(
				[]byte{byte(sema_codec.EncodedSemaGenericType)},
				[]byte{0, 0, 0, byte(len(name))},
				[]byte(name),
				[]byte{byte(sema_codec.EncodedSemaNumericTypeInt32Type)},
				[]byte{byte(sema_codec.EncodedBoolTrue)},
			)...,
		)
	})

	t.Run("FunctionType", func(t *testing.T) {
		t.Parallel()

		const isConstructor = true
		typeParameters := []*sema.TypeParameter{
			{
				Name:      "myriad",
				TypeBound: sema.VoidType,
				Optional:  false,
			},
		}
		parameters := []*sema.Parameter{
			{
				Label:          "juno",
				Identifier:     "fake0",
				TypeAnnotation: sema.NewTypeAnnotation(sema.AnyResourceType),
			},
			{
				Label:          "calipso",
				Identifier:     "fake1",
				TypeAnnotation: sema.NewTypeAnnotation(sema.StringType),
			},
		}
		returnTypeAnnotation := sema.NewTypeAnnotation(sema.PathType)
		requiredArgumentCount := 1

		members := sema.NewStringMemberOrderedMap()
		memberIdentifer := "someID"
		memberDocString := "\"doctored\" string"
		members.Set("yolo", sema.NewPublicConstantFieldMember(
			nil,
			sema.PrivatePathType,
			memberIdentifer,
			sema.Int8Type,
			memberDocString,
		))

		functionType := &sema.FunctionType{
			IsConstructor:            isConstructor,
			TypeParameters:           typeParameters,
			Parameters:               parameters,
			ReturnTypeAnnotation:     returnTypeAnnotation,
			RequiredArgumentCount:    &requiredArgumentCount,
			ArgumentExpressionsCheck: nil,
			Members:                  members,
		}

		encoder, decoder, buffer := NewTestCodec()

		err := encoder.Encode(functionType)
		require.NoError(t, err, "encoding error")

		expected := Concat(
			[]byte{byte(sema_codec.EncodedSemaFunctionType)},

			[]byte{byte(sema_codec.EncodedBoolTrue)}, // isConstructor

			[]byte{byte(sema_codec.EncodedBoolFalse)}, // TypeParameters array is non-nil
			[]byte{0, 0, 0, byte(len(typeParameters))},
			[]byte{0, 0, 0, byte(len(typeParameters[0].Name))},
			[]byte(typeParameters[0].Name),
			[]byte{byte(sema_codec.EncodedSemaSimpleTypeVoidType)},
			[]byte{byte(sema_codec.EncodedBoolFalse)},

			[]byte{byte(sema_codec.EncodedBoolFalse)}, // Parameters array is non-nil
			[]byte{0, 0, 0, byte(len(parameters))},
			[]byte{0, 0, 0, byte(len(parameters[0].Label))},
			[]byte(parameters[0].Label),
			[]byte{0, 0, 0, byte(len(parameters[0].Identifier))},
			[]byte(parameters[0].Identifier),
			[]byte{byte(sema_codec.EncodedBoolTrue)},
			[]byte{byte(sema_codec.EncodedSemaSimpleTypeAnyResourceType)},
			[]byte{0, 0, 0, byte(len(parameters[1].Label))},
			[]byte(parameters[1].Label),
			[]byte{0, 0, 0, byte(len(parameters[1].Identifier))},
			[]byte(parameters[1].Identifier),
			[]byte{byte(sema_codec.EncodedBoolFalse)},
			[]byte{byte(sema_codec.EncodedSemaSimpleTypeStringType)},

			[]byte{byte(sema_codec.EncodedBoolFalse)}, // TypeAnnotation: it is not a Resource
			[]byte{byte(sema_codec.EncodedSemaSimpleTypePathType)},

			[]byte{0, 0, 0, 0, 0, 0, 0, byte(requiredArgumentCount)},

			[]byte{0, 0, 0, byte(members.Len())},             // Members length
			[]byte{0, 0, 0, byte(len(members.Newest().Key))}, // Member key
			[]byte(members.Newest().Key),
			[]byte{0, 0, 0, 0, 0, 0, 0, byte(ast.AccessPublic)}, // Member value
			[]byte{0, 0, 0, byte(len(memberIdentifer))},         // Member AST identifier
			[]byte(memberIdentifer),
			[]byte{0, 0, 0, 0, 0, 0, 0, 0}, // Member AST identifier position
			[]byte{0, 0, 0, 0, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0},
			[]byte{byte(sema_codec.EncodedBoolFalse)}, // Member type annotation
			[]byte{byte(sema_codec.EncodedSemaNumericTypeInt8Type)},
			[]byte{0, 0, 0, 0, 0, 0, 0, byte(common.DeclarationKindField)}, // Member declaration kind
			[]byte{0, 0, 0, 0, 0, 0, 0, byte(ast.VariableKindConstant)},    // member variable kind
			[]byte{byte(sema_codec.EncodedBoolTrue)},                       // Member has no argument labels
			[]byte{byte(sema_codec.EncodedBoolFalse)},                      // Member is not predeclared
			[]byte{0, 0, 0, byte(len(memberDocString))},                    // Member doc string
			[]byte(memberDocString),
		)

		assert.Equal(t, expected, buffer.Bytes(), "encoded bytes differ")

		decoded, err := decoder.Decode()
		require.NoError(t, err, "decoding error")

		// Cannot simply check equality between original and decoded types because they are not shallowly equal.
		// Specifically, RequiredArgumentCount and Members are not shallowly equal.
		switch f := decoded.(type) {
		case *sema.FunctionType:
			assert.Equal(t, isConstructor, f.IsConstructor)

			require.NotNil(t, f.TypeParameters, "TypeParameters")
			require.Len(t, f.TypeParameters, 1, "TypeParameters")
			assert.Equal(t, typeParameters[0], f.TypeParameters[0], "TypeParameters[0]")

			require.NotNil(t, f.Parameters, "Parameters")
			require.Len(t, f.Parameters, 2, "Parameters")
			assert.Equal(t, parameters[0], f.Parameters[0], "Parameters[0]")
			assert.Equal(t, parameters[1], f.Parameters[1], "Parameters[1]")

			assert.Equal(t, returnTypeAnnotation, f.ReturnTypeAnnotation, "ReturnTypeAnnotation")

			assert.Equal(t, requiredArgumentCount, *f.RequiredArgumentCount, "RequiredArgumentCount")

			assert.Nil(t, f.ArgumentExpressionsCheck, "ArgumentExpressionsCheck")

			// verify member equality
			require.Equal(t, members.Len(), f.Members.Len(), "members length")
			f.Members.Foreach(func(key string, actual *sema.Member) {
				expected, present := f.Members.Get(key)
				require.True(t, present, "extra member: %s", key)

				assert.Equal(t, expected.ContainerType.ID(), actual.ContainerType.ID(), "container type for %s", key)
				assert.Equal(t, expected.TypeAnnotation.QualifiedString(), actual.TypeAnnotation.QualifiedString(), "type annotation for %s", key)
			})
		default:
			assert.Fail(t, "Decoded type is not *sema.FunctionTypre")
		}
	})

	t.Run("DictionaryType", func(t *testing.T) {
		t.Parallel()

		testRootEncodeDecode(
			t,
			&sema.DictionaryType{
				KeyType:   sema.StringType,
				ValueType: sema.AnyStructType,
			},
			Concat(
				[]byte{byte(sema_codec.EncodedSemaDictionaryType)},
				[]byte{byte(sema_codec.EncodedSemaSimpleTypeStringType)},
				[]byte{byte(sema_codec.EncodedSemaSimpleTypeAnyStructType)},
			)...,
		)
	})

	t.Run("TransactionType", func(t *testing.T) {
		t.Parallel()

		members := sema.NewStringMemberOrderedMap()
		memberIdentifer := "someID"
		memberDocString := "\"doctored\" string"
		members.Set("yol2", sema.NewPublicConstantFieldMember(
			nil,
			sema.PrivatePathType,
			memberIdentifer,
			sema.Int8Type,
			memberDocString,
		))

		fields := []string{
			"twelve",
			"twenty four",
			"forty eight",
			"ninety six",
		}

		prepareParameters := []*sema.Parameter{
			{
				Label:          "replay",
				Identifier:     "fake6",
				TypeAnnotation: sema.NewTypeAnnotation(sema.UInt16Type),
			},
		}

		parameters := []*sema.Parameter{
			{
				Label:          "hadron",
				Identifier:     "collision",
				TypeAnnotation: sema.NewTypeAnnotation(sema.SignedFixedPointType),
			},
		}

		transactionType := &sema.TransactionType{
			Members:           members,
			Fields:            fields,
			PrepareParameters: prepareParameters,
			Parameters:        parameters,
		}

		encoder, decoder, buffer := NewTestCodec()

		err := encoder.Encode(transactionType)
		require.NoError(t, err, "encoding error")

		expected := Concat(
			[]byte{byte(sema_codec.EncodedSemaTransactionType)},
			// members
			[]byte{0, 0, 0, byte(members.Len())},             // Members length
			[]byte{0, 0, 0, byte(len(members.Newest().Key))}, // Member key
			[]byte(members.Newest().Key),
			[]byte{0, 0, 0, 0, 0, 0, 0, byte(ast.AccessPublic)}, // Member value
			[]byte{0, 0, 0, byte(len(memberIdentifer))},         // Member AST identifier
			[]byte(memberIdentifer),
			[]byte{0, 0, 0, 0, 0, 0, 0, 0}, // Member AST identifier position
			[]byte{0, 0, 0, 0, 0, 0, 0, 0},
			[]byte{0, 0, 0, 0, 0, 0, 0, 0},
			[]byte{byte(sema_codec.EncodedBoolFalse)}, // Member type annotation
			[]byte{byte(sema_codec.EncodedSemaNumericTypeInt8Type)},
			[]byte{0, 0, 0, 0, 0, 0, 0, byte(common.DeclarationKindField)}, // Member declaration kind
			[]byte{0, 0, 0, 0, 0, 0, 0, byte(ast.VariableKindConstant)},    // member variable kind
			[]byte{byte(sema_codec.EncodedBoolTrue)},                       // Member has no argument labels
			[]byte{byte(sema_codec.EncodedBoolFalse)},                      // Member is not predeclared
			[]byte{0, 0, 0, byte(len(memberDocString))},                    // Member doc string
			[]byte(memberDocString),

			// array of strings for fields
			[]byte{byte(sema_codec.EncodedBoolFalse)}, // array is not nil
			[]byte{0, 0, 0, byte(len(fields))},
			[]byte{0, 0, 0, byte(len(fields[0]))},
			[]byte(fields[0]),
			[]byte{0, 0, 0, byte(len(fields[1]))},
			[]byte(fields[1]),
			[]byte{0, 0, 0, byte(len(fields[2]))},
			[]byte(fields[2]),
			[]byte{0, 0, 0, byte(len(fields[3]))},
			[]byte(fields[3]),

			// array of parameters for prepareParameters
			[]byte{byte(sema_codec.EncodedBoolFalse)}, // array is not nil
			[]byte{0, 0, 0, byte(len(prepareParameters))},
			[]byte{0, 0, 0, byte(len(prepareParameters[0].Label))},
			[]byte(prepareParameters[0].Label),
			[]byte{0, 0, 0, byte(len(prepareParameters[0].Identifier))},
			[]byte(prepareParameters[0].Identifier),
			[]byte{byte(sema_codec.EncodedBoolFalse)},
			[]byte{byte(sema_codec.EncodedSemaNumericTypeUInt16Type)},

			// array of parameters for parameters
			[]byte{byte(sema_codec.EncodedBoolFalse)}, // array is not nil
			[]byte{0, 0, 0, byte(len(parameters))},
			[]byte{0, 0, 0, byte(len(parameters[0].Label))},
			[]byte(parameters[0].Label),
			[]byte{0, 0, 0, byte(len(parameters[0].Identifier))},
			[]byte(parameters[0].Identifier),
			[]byte{byte(sema_codec.EncodedBoolFalse)},
			[]byte{byte(sema_codec.EncodedSemaNumericTypeSignedFixedPointType)},
		)

		assert.Equal(t, expected, buffer.Bytes(), "encoded bytes differ")

		decoded, err := decoder.Decode()
		require.NoError(t, err, "decoding error")

		// Cannot simply check equality between original and decoded types because they are not shallowly equal.
		// Specifically, Members is not shallowly equal.
		switch tx := decoded.(type) {
		case *sema.TransactionType:
			// verify member equality
			require.Equal(t, members.Len(), tx.Members.Len(), "members length")
			tx.Members.Foreach(func(key string, actual *sema.Member) {
				expected, present := tx.Members.Get(key)
				require.True(t, present, "extra member: %s", key)

				assert.Equal(t, expected.ContainerType.ID(), actual.ContainerType.ID(), "container type for %s", key)
				assert.Equal(t, expected.TypeAnnotation.QualifiedString(), actual.TypeAnnotation.QualifiedString(), "type annotation for %s", key)
			})

			assert.Equal(t, fields, tx.Fields, "fields")
			assert.Equal(t, tx.Parameters, parameters, "parameters")
			assert.Equal(t, tx.PrepareParameters, prepareParameters, "prepareParameters")
		default:
			assert.Fail(t, "Decoded type is not *sema.TransactionType")
		}
	})

	t.Run("RestrictedType", func(t *testing.T) {
		t.Parallel()

		restriction := sema.PublicKeyType.InterfaceType()
		restrictedType := &sema.RestrictedType{
			Type:         sema.IntType,
			Restrictions: []*sema.InterfaceType{restriction},
		}

		encoder, decoder, buffer := NewTestCodec()

		err := encoder.Encode(restrictedType)
		require.NoError(t, err, "encoding error")

		encodedRestriction := sema_codec.MustEncodeSema(restriction)
		encodedRestriction = encodedRestriction[1:] // remove leading type identifier

		expected := Concat(
			[]byte{byte(sema_codec.EncodedSemaRestrictedType)},
			[]byte{byte(sema_codec.EncodedSemaNumericTypeIntType)},
			[]byte{byte(sema_codec.EncodedBoolFalse)}, // array is not nil
			[]byte{0, 0, 0, 1}, // array length
			encodedRestriction,
		)

		assert.Equal(t, expected, buffer.Bytes(), "encoded bytes differ")

		decoded, err := decoder.Decode()
		require.NoError(t, err, "decoding error")

		// Cannot simply check equality between original and decoded types because they are not shallowly equal.
		// Specifically, the elements of Restrictions are not shallowly equal.
		switch r := decoded.(type) {
		case *sema.RestrictedType:
			assert.Equal(t, sema.IntType, r.Type, "Type")

			require.Len(t, r.Restrictions, 1, "restrictions length")

			// minimal verification
			assert.Equal(t, sema.PublicKeyType.Identifier, r.Restrictions[0].Identifier, "restriction identifier")
		default:
			assert.Fail(t, "Decoded type is not *sema.RestrictionType")
		}
	})
}

func TestSemaCodecBadTypes(t *testing.T) {
	t.Parallel()

	t.Run("unknown type", func(t *testing.T) {
		t.Skip("TODO")
	})

	t.Run("bad type", func(t *testing.T) {
		t.Skip("TODO")
	})
}

func TestSemaCodecArrayTypes(t *testing.T) {
	// TODO also nil arrays
	t.Run("variable", func(t *testing.T) {
		t.Parallel()

		testRootEncodeDecode(
			t,
			&sema.VariableSizedType{Type: sema.CharacterType},
			byte(sema_codec.EncodedSemaVariableSizedType),
			byte(sema_codec.EncodedSemaSimpleTypeCharacterType),
		)
	})

	t.Run("constant", func(t *testing.T) {
		t.Parallel()

		testRootEncodeDecode(
			t,
			&sema.ConstantSizedType{
				Type: sema.CharacterType,
				Size: 90,
			},
			byte(sema_codec.EncodedSemaConstantSizedType),
			byte(sema_codec.EncodedSemaSimpleTypeCharacterType),
			0, 0, 0, 0, 0, 0, 0, byte(90),
		)
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

	t.Run("string len=0", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		testEncodeDecode(
			t,
			"",
			buffer,
			encoder.EncodeString,
			decoder.DecodeString,
			[]byte{0, 0, 0, 0},
		)
	})

	t.Run("bytes", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		b := []byte("some bytes \x00 foo \t \n\r\n $ 5")

		testEncodeDecode(
			t,
			b,
			buffer,
			encoder.EncodeBytes,
			decoder.DecodeBytes,
			append(
				[]byte{0, 0, 0, byte(len(b))},
				b...,
			),
		)
	})

	t.Run("bool true", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		testEncodeDecode(
			t,
			true,
			buffer,
			encoder.EncodeBool,
			decoder.DecodeBool,
			[]byte{byte(sema_codec.EncodedBoolTrue)},
		)
	})

	t.Run("bool false", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		testEncodeDecode(
			t,
			false,
			buffer,
			encoder.EncodeBool,
			decoder.DecodeBool,
			[]byte{byte(sema_codec.EncodedBoolFalse)},
		)
	})

	t.Run("uint64", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		i := uint64(1<<63) + 17

		testEncodeDecode(
			t,
			i,
			buffer,
			encoder.EncodeUInt64,
			decoder.DecodeUInt64,
			[]byte{128, 0, 0, 0, 0, 0, 0, 17},
		)
	})

	t.Run("int64 positive", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		i := int64(1<<62) + 17

		testEncodeDecode(
			t,
			i,
			buffer,
			encoder.EncodeInt64,
			decoder.DecodeInt64,
			[]byte{64, 0, 0, 0, 0, 0, 0, 17},
		)
	})

	t.Run("int64 negative", func(t *testing.T) {
		t.Parallel()

		encoder, decoder, buffer := NewTestCodec()

		i := -(int64(1<<62) + 17)

		testEncodeDecode(
			t,
			i,
			buffer,
			encoder.EncodeInt64,
			decoder.DecodeInt64,
			[]byte{0xff - 64, 0xff - 0, 0xff - 0, 0xff - 0, 0xff - 0, 0xff - 0, 0xff - 0, 0xff - 17 + 1},
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
		sema_codec.NilLocationPrefix,
	} {
		t.Run(fmt.Sprintf("prefix: %s", prefix), func(t *testing.T) {
			t.Parallel()

			encoder, decoder, buffer := NewTestCodec()

			testEncodeDecode(
				t,
				sema_codec.NilLocationPrefix,
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
			[]byte{sema_codec.NilLocationPrefix[0]},
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

func TestSemaCodecInterfaceType(t *testing.T) {
	t.Parallel()

	location := common.TransactionLocation{1, 3, 9, 27, 81}

	identifier := "murakami"

	members := sema.NewStringMemberOrderedMap()
	memberIdentifer := "someID"
	memberDocString := "\"doctored\" string"
	members.Set("yolo", sema.NewPublicConstantFieldMember(
		nil,
		sema.PrivatePathType,
		memberIdentifer,
		sema.Int8Type,
		memberDocString,
	))

	fields := []string{"dance"}

	parameters := []*sema.Parameter{
		{
			Label:          "lol",
			Identifier:     "haha",
			TypeAnnotation: sema.NewTypeAnnotation(sema.NeverType),
		},
	}

	interfaceType := &sema.InterfaceType{
		Location:              location,
		Identifier:            identifier,
		CompositeKind:         common.CompositeKindEnum,
		Members:               members,
		Fields:                fields,
		InitializerParameters: parameters,
	}

	// TODO container type
	//container := sema.AuthAccountType
	//interfaceType.SetContainerType(container)

	encoder, decoder, buffer := NewTestCodec()

	err := encoder.Encode(interfaceType)
	require.NoError(t, err, "encoding error")

	expected := Concat(
		[]byte{byte(sema_codec.EncodedSemaInterfaceType)},

		[]byte{common.TransactionLocationPrefix[0]},
		[]byte{0, 0, 0, byte(len(location))},
		location,

		[]byte{0, 0, 0, byte(len(identifier))},
		[]byte(identifier),

		[]byte{0, 0, 0, 0, 0, 0, 0, byte(common.CompositeKindEnum)},

		[]byte{0, 0, 0, byte(members.Len())},             // Members length
		[]byte{0, 0, 0, byte(len(members.Newest().Key))}, // Member key
		[]byte(members.Newest().Key),
		[]byte{0, 0, 0, 0, 0, 0, 0, byte(ast.AccessPublic)}, // Member value
		[]byte{0, 0, 0, byte(len(memberIdentifer))},         // Member AST identifier
		[]byte(memberIdentifer),
		[]byte{0, 0, 0, 0, 0, 0, 0, 0}, // Member AST identifier position
		[]byte{0, 0, 0, 0, 0, 0, 0, 0},
		[]byte{0, 0, 0, 0, 0, 0, 0, 0},
		[]byte{byte(sema_codec.EncodedBoolFalse)}, // Member type annotation
		[]byte{byte(sema_codec.EncodedSemaNumericTypeInt8Type)},
		[]byte{0, 0, 0, 0, 0, 0, 0, byte(common.DeclarationKindField)}, // Member declaration kind
		[]byte{0, 0, 0, 0, 0, 0, 0, byte(ast.VariableKindConstant)},    // member variable kind
		[]byte{byte(sema_codec.EncodedBoolTrue)},                       // Member has no argument labels
		[]byte{byte(sema_codec.EncodedBoolFalse)},                      // Member is not predeclared
		[]byte{0, 0, 0, byte(len(memberDocString))},                    // Member doc string
		[]byte(memberDocString),

		[]byte{byte(sema_codec.EncodedBoolFalse)}, // array is not nil
		[]byte{0, 0, 0, byte(len(fields))},
		[]byte{0, 0, 0, byte(len(fields[0]))},
		[]byte(fields[0]),

		[]byte{byte(sema_codec.EncodedBoolFalse)}, // array is not nil
		[]byte{0, 0, 0, byte(len(parameters))},
		[]byte{0, 0, 0, byte(len(parameters[0].Label))},
		[]byte(parameters[0].Label),
		[]byte{0, 0, 0, byte(len(parameters[0].Identifier))},
		[]byte(parameters[0].Identifier),
		[]byte{byte(sema_codec.EncodedBoolFalse)},
		[]byte{byte(sema_codec.EncodedSemaSimpleTypeNeverType)},

		[]byte{byte(sema_codec.EncodedSemaNilType)}, // no container type
	)

	assert.Equal(t, expected, buffer.Bytes(), "encoded bytes differ")

	decoded, err := decoder.Decode()
	require.NoError(t, err, "decoding error")

	// Cannot simply check equality between original and decoded types because they are not shallowly equal.
	// Specifically, RequiredArgumentCount and Members are not shallowly equal.
	switch i := decoded.(type) {
	case *sema.InterfaceType:
		assert.Equal(t, location, i.Location, "location")

		assert.Equal(t, identifier, i.Identifier, "identifier")

		assert.Equal(t, common.CompositeKindEnum, i.CompositeKind, "composite kind")

		// verify member equality
		require.Equal(t, members.Len(), i.Members.Len(), "members length")
		i.Members.Foreach(func(key string, actual *sema.Member) {
			expected, present := i.Members.Get(key)
			require.True(t, present, "extra member: %s", key)

			assert.Equal(t, expected.ContainerType.ID(), actual.ContainerType.ID(), "container type for %s", key)
			assert.Equal(t, expected.TypeAnnotation.QualifiedString(), actual.TypeAnnotation.QualifiedString(), "type annotation for %s", key)
		})

		assert.Equal(t, fields, i.Fields, "fields")

		assert.Equal(t, parameters, i.InitializerParameters, "parameters")

		assert.Nil(t, i.GetContainerType(), "container type")
	default:
		assert.Fail(t, "Decoded type is not *sema.InterfaceType")
	}
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
		byte(sema_codec.EncodedSemaCompositeType),

		// location
		sema_codec.NilLocationPrefix[0],

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
		byte(sema_codec.EncodedBoolTrue),

		// ImplicitTypeRequirementConformances array is nil
		byte(sema_codec.EncodedBoolTrue),
	}
	assert.Equal(t, expected, buffer.Bytes()[:len(expected)], "encoded bytes")

	decoder := sema_codec.NewSemaDecoder(nil, buffer)
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

func TestSemaCodecRecursiveType(t *testing.T) {
	t.Parallel()

	t.Skip("TODO")

	// TODO describe a type that contains itself
	//      this is needed because that's possible but not yet supported by the codec
}

//
// Helpers
//

func testRootEncodeDecode(
	t *testing.T,
	input sema.Type,
	expectedEncoding ...byte,
) ([]byte, sema.Type) {
	blob, err := sema_codec.EncodeSema(input)
	require.NoError(t, err, "encoding error")

	if expectedEncoding != nil {
		assert.Equal(t, expectedEncoding, blob)
	}

	output, err := sema_codec.DecodeSema(nil, blob)
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

func NewTestEncoder() (*sema_codec.SemaEncoder, *bytes.Buffer) {
	var w bytes.Buffer
	encoder := sema_codec.NewSemaEncoder(&w)
	return encoder, &w
}

func NewTestCodec() (encoder *sema_codec.SemaEncoder, decoder *sema_codec.SemaDecoder, buffer *bytes.Buffer) {
	var w bytes.Buffer
	buffer = &w
	encoder = sema_codec.NewSemaEncoder(buffer)
	decoder = sema_codec.NewSemaDecoder(nil, buffer)
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
