package sema_codec

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/onflow/cadence/runtime/ast"
	"github.com/onflow/cadence/runtime/common"
	"github.com/onflow/cadence/runtime/sema"
	"io"
	"math/big"
	goRuntime "runtime"
)

type LengthyWriter struct {
	w      io.Writer
	length int
}

func (l *LengthyWriter) Write(p []byte) (n int, err error) {
	n, err = l.w.Write(p)
	l.length += n
	return
}

// A SemaEncoder converts Sema types into custom-encoded bytes.
type SemaEncoder struct {
	w        LengthyWriter
	typeDefs map[sema.Type]int
}

// EncodeSema returns the custom-encoded representation of the given sema type.
//
// This function returns an error if the Cadence value cannot be represented in the custom format.
func EncodeSema(t sema.Type) ([]byte, error) {
	var w bytes.Buffer
	enc := NewSemaEncoder(&w)

	err := enc.Encode(t)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// MustEncodeSema returns the custom-encoded representation of the given sema type, or panics
// if the sema type cannot be represented in the custom format.
func MustEncodeSema(value sema.Type) []byte {
	b, err := EncodeSema(value)
	if err != nil {
		panic(err)
	}
	return b
}

// NewSemaEncoder initializes a SemaEncoder that will write custom-encoded bytes to the
// given io.Writer.
func NewSemaEncoder(w io.Writer) *SemaEncoder {
	return &SemaEncoder{w: LengthyWriter{w: w}, typeDefs: map[sema.Type]int{}}
}

// Encode writes the custom-encoded representation of the given sema type to this
// encoder's io.Writer.
//
// This function returns an error if the given sema type is not supported
// by this encoder.
func (e *SemaEncoder) Encode(t sema.Type) (err error) {
	// capture panics that occur during struct preparation
	defer func() {
		if r := recover(); r != nil {
			// don't recover Go errors
			goErr, ok := r.(goRuntime.Error)
			if ok {
				panic(goErr)
			}

			panicErr, isError := r.(error)
			if !isError {
				panic(r)
			}

			err = fmt.Errorf("failed to encode value: %w", panicErr)
		}
	}()

	return e.EncodeType(t)
}

// EncodeType encodes any supported sema.Type.
// Includes concrete type identifier because "Type" is an abstract type
// ergo it can't be instantiated on decode.
func (e *SemaEncoder) EncodeType(t sema.Type) (err error) {
	if isPointableType(t) {
		if bufferOffset, usePointer := e.typeDefs[t]; usePointer {
			return e.EncodePointer(bufferOffset)
		} else {
			e.typeDefs[t] = e.w.length
		}
	}

	err = e.EncodeTypeIdentifier(t)
	if err != nil {
		return
	}

	switch concreteType := t.(type) {
	case *sema.AddressType, *sema.SimpleType, *sema.NumericType, *sema.FixedPointNumericType, nil:
		return // already encoded by EncodeTypeIdentifier
	case *sema.OptionalType:
		return e.EncodeOptionalType(concreteType)
	case *sema.ReferenceType:
		return e.EncodeReferenceType(concreteType)
	case *sema.CapabilityType:
		return e.EncodeCapabilityType(concreteType)
	case *sema.VariableSizedType:
		return e.EncodeVariableSizedType(concreteType)

	case *sema.CompositeType:
		return e.EncodeCompositeType(concreteType)
	case *sema.InterfaceType:
		return e.EncodeInterfaceType(concreteType)
	case *sema.GenericType:
		return e.EncodeGenericType(concreteType)
	case *sema.FunctionType:
		return e.EncodeFunctionType(concreteType)
	case *sema.DictionaryType:
		return e.EncodeDictionaryType(concreteType)
	case *sema.TransactionType:
		return e.EncodeTransactionType(concreteType)
	case *sema.RestrictedType:
		return e.EncodeRestrictedType(concreteType)
	case *sema.ConstantSizedType:
		return e.EncodeConstantSizedType(concreteType)

	default:
		return fmt.Errorf("unexpected type: %s", concreteType)
	}
}

// TODO add protections against regressions from changes to enum
// TODO consider putting simple and numeric types in a specific ranges (128+, 64-127)
//      that turns certain bits into flags for the presence of those types, which can be calculated very fast
//      (check the leftmost bit first, then the next bit, in that order, or there's overlap)
type EncodedSema byte

const (
	EncodedSemaUnknown EncodedSema = iota // lacking type information; should not be encoded

	// Simple Types

	EncodedSemaSimpleTypeAnyType
	EncodedSemaSimpleTypeAnyResourceType
	EncodedSemaSimpleTypeAnyStructType
	EncodedSemaSimpleTypeBlockType
	EncodedSemaSimpleTypeBoolType
	EncodedSemaSimpleTypeCharacterType
	EncodedSemaSimpleTypeDeployedContractType
	EncodedSemaSimpleTypeInvalidType
	EncodedSemaSimpleTypeMetaType
	EncodedSemaSimpleTypeNeverType
	EncodedSemaSimpleTypePathType
	EncodedSemaSimpleTypeStoragePathType
	EncodedSemaSimpleTypeCapabilityPathType
	EncodedSemaSimpleTypePublicPathType
	EncodedSemaSimpleTypePrivatePathType
	EncodedSemaSimpleTypeStorableType
	EncodedSemaSimpleTypeStringType
	EncodedSemaSimpleTypeVoidType

	// Numeric Types

	EncodedSemaNumericTypeNumberType
	EncodedSemaNumericTypeSignedNumberType
	EncodedSemaNumericTypeIntegerType
	EncodedSemaNumericTypeSignedIntegerType
	EncodedSemaNumericTypeIntType
	EncodedSemaNumericTypeInt8Type
	EncodedSemaNumericTypeInt16Type
	EncodedSemaNumericTypeInt32Type
	EncodedSemaNumericTypeInt64Type
	EncodedSemaNumericTypeInt128Type
	EncodedSemaNumericTypeInt256Type
	EncodedSemaNumericTypeUIntType
	EncodedSemaNumericTypeUInt8Type
	EncodedSemaNumericTypeUInt16Type
	EncodedSemaNumericTypeUInt32Type
	EncodedSemaNumericTypeUInt64Type
	EncodedSemaNumericTypeUInt128Type
	EncodedSemaNumericTypeUInt256Type
	EncodedSemaNumericTypeWord8Type
	EncodedSemaNumericTypeWord16Type
	EncodedSemaNumericTypeWord32Type
	EncodedSemaNumericTypeWord64Type
	EncodedSemaNumericTypeFixedPointType
	EncodedSemaNumericTypeSignedFixedPointType

	EncodedSemaFix64Type
	EncodedSemaUFix64Type

	// Pointable Types
	EncodedSemaCompositeType
	EncodedSemaInterfaceType
	EncodedSemaGenericType

	// Other Types

	EncodedSemaNilType // no type is specified
	EncodedSemaOptionalType

	EncodedSemaVariableSizedType
	EncodedSemaConstantSizedType
	EncodedSemaFunctionType
	EncodedSemaDictionaryType
	EncodedSemaReferenceType
	EncodedSemaAddressType
	EncodedSemaTransactionType
	EncodedSemaRestrictedType
	EncodedSemaCapabilityType
	EncodedSemaPointerType
)

func isSimpleType(encodedSema EncodedSema) bool {
	return encodedSema >= EncodedSemaSimpleTypeAnyType &&
		encodedSema <= EncodedSemaSimpleTypeVoidType
}

func isNumericType(encodedSema EncodedSema) bool {
	return encodedSema >= EncodedSemaNumericTypeNumberType &&
		encodedSema <= EncodedSemaNumericTypeSignedFixedPointType
}

func isFixedPointNumericType(encodedSema EncodedSema) bool {
	return encodedSema == EncodedSemaFix64Type || encodedSema == EncodedSemaUFix64Type
}

// TODO determine if more types need to be pointable to reproduce correct object grpah on decode
func isPointableType(t sema.Type) bool {
	switch t.(type) {
	case *sema.CompositeType,
		*sema.GenericType,
		*sema.FunctionType,
		*sema.DictionaryType,
		*sema.TransactionType,
		*sema.RestrictedType,
		*sema.ConstantSizedType:
		return true
	default:
		return false
	}
}

func (e *SemaEncoder) EncodeSimpleType(t *sema.SimpleType) (err error) {
	subType := EncodedSemaUnknown

	switch t {
	case sema.AnyType:
		subType = EncodedSemaSimpleTypeAnyType
	case sema.AnyResourceType:
		subType = EncodedSemaSimpleTypeAnyResourceType
	case sema.AnyStructType:
		subType = EncodedSemaSimpleTypeAnyStructType
	case sema.BlockType:
		subType = EncodedSemaSimpleTypeBlockType
	case sema.BoolType:
		subType = EncodedSemaSimpleTypeBoolType
	case sema.CharacterType:
		subType = EncodedSemaSimpleTypeCharacterType
	case sema.DeployedContractType:
		subType = EncodedSemaSimpleTypeDeployedContractType
	case sema.InvalidType:
		subType = EncodedSemaSimpleTypeInvalidType
	case sema.MetaType:
		subType = EncodedSemaSimpleTypeMetaType
	case sema.NeverType:
		subType = EncodedSemaSimpleTypeNeverType
	case sema.PathType:
		subType = EncodedSemaSimpleTypePathType
	case sema.StoragePathType:
		subType = EncodedSemaSimpleTypeStoragePathType
	case sema.CapabilityPathType:
		subType = EncodedSemaSimpleTypeCapabilityPathType
	case sema.PublicPathType:
		subType = EncodedSemaSimpleTypePublicPathType
	case sema.PrivatePathType:
		subType = EncodedSemaSimpleTypePrivatePathType
	case sema.StorableType:
		subType = EncodedSemaSimpleTypeStorableType
	case sema.StringType:
		subType = EncodedSemaSimpleTypeStringType
	case sema.VoidType:
		subType = EncodedSemaSimpleTypeVoidType

	default:
		return fmt.Errorf("unknown simple type: %s", t)
	}

	return e.write([]byte{byte(subType)})
}

func (e *SemaEncoder) EncodeFunctionType(t *sema.FunctionType) (err error) {
	err = e.EncodeBool(t.IsConstructor)
	if err != nil {
		return
	}

	err = EncodeArray(e, t.TypeParameters, e.EncodeTypeParameter)
	if err != nil {
		return
	}

	err = EncodeArray(e, t.Parameters, e.EncodeParameter)
	if err != nil {
		return
	}

	err = e.EncodeTypeAnnotation(t.ReturnTypeAnnotation)
	if err != nil {
		return
	}

	if t.RequiredArgumentCount == nil {
		err = e.EncodeInt64(0)
		if err != nil {
			return
		}
	} else {
		err = e.EncodeInt64(int64(*t.RequiredArgumentCount))
		if err != nil {
			return
		}
	}

	// TODO Is it OK that ArgumentExpressionCheck is omitted?
	//      I only see it set twice: AddressConversionFunctionType and NumberConversionFunctionType
	//      It is likely that these should be encoded as enums instead, since they are Cadence globals.

	return e.EncodeStringMemberOrderedMap(t.Members)
}

func (e *SemaEncoder) EncodeDictionaryType(t *sema.DictionaryType) (err error) {
	err = e.EncodeType(t.KeyType)
	if err != nil {
		return
	}

	return e.EncodeType(t.ValueType)
}

func (e *SemaEncoder) EncodeReferenceType(t *sema.ReferenceType) (err error) {
	err = e.EncodeBool(t.Authorized)
	if err != nil {
		return
	}

	return e.EncodeType(t.Type)
}

func (e *SemaEncoder) EncodeTransactionType(t *sema.TransactionType) (err error) {
	err = e.EncodeStringMemberOrderedMap(t.Members)
	if err != nil {
		return
	}

	err = EncodeArray(e, t.Fields, e.EncodeString)
	if err != nil {
		return
	}

	err = EncodeArray(e, t.PrepareParameters, e.EncodeParameter)
	if err != nil {
		return
	}

	return EncodeArray(e, t.Parameters, e.EncodeParameter)
}

func (e *SemaEncoder) EncodeRestrictedType(t *sema.RestrictedType) (err error) {
	err = e.EncodeType(t.Type)
	if err != nil {
		return
	}

	return EncodeArray(e, t.Restrictions, e.EncodeInterfaceType)
}

func (e *SemaEncoder) EncodeCapabilityType(t *sema.CapabilityType) (err error) {
	return e.EncodeType(t.BorrowType)
}

func (e *SemaEncoder) EncodeOptionalType(t *sema.OptionalType) (err error) {
	return e.EncodeType(t.Type)
}

func (e *SemaEncoder) EncodeVariableSizedType(t *sema.VariableSizedType) (err error) {
	return e.EncodeType(t.Type)
}

func (e *SemaEncoder) EncodeConstantSizedType(t *sema.ConstantSizedType) (err error) {
	err = e.EncodeType(t.Type)
	if err != nil {
		return
	}

	return e.EncodeInt64(t.Size)
}

func (e *SemaEncoder) EncodeGenericType(t *sema.GenericType) (err error) {
	return e.EncodeTypeParameter(t.TypeParameter)
}

func (e *SemaEncoder) EncodeNumericType(t *sema.NumericType) (err error) {
	numericType := EncodedSemaUnknown

	switch t {
	case sema.NumberType:
		numericType = EncodedSemaNumericTypeNumberType
	case sema.SignedNumberType:
		numericType = EncodedSemaNumericTypeSignedNumberType
	case sema.IntegerType:
		numericType = EncodedSemaNumericTypeIntegerType
	case sema.SignedIntegerType:
		numericType = EncodedSemaNumericTypeSignedIntegerType
	case sema.IntType:
		numericType = EncodedSemaNumericTypeIntType
	case sema.Int8Type:
		numericType = EncodedSemaNumericTypeInt8Type
	case sema.Int16Type:
		numericType = EncodedSemaNumericTypeInt16Type
	case sema.Int32Type:
		numericType = EncodedSemaNumericTypeInt32Type
	case sema.Int64Type:
		numericType = EncodedSemaNumericTypeInt64Type
	case sema.Int128Type:
		numericType = EncodedSemaNumericTypeInt128Type
	case sema.Int256Type:
		numericType = EncodedSemaNumericTypeInt256Type
	case sema.UIntType:
		numericType = EncodedSemaNumericTypeUIntType
	case sema.UInt8Type:
		numericType = EncodedSemaNumericTypeUInt8Type
	case sema.UInt16Type:
		numericType = EncodedSemaNumericTypeUInt16Type
	case sema.UInt32Type:
		numericType = EncodedSemaNumericTypeUInt32Type
	case sema.UInt64Type:
		numericType = EncodedSemaNumericTypeUInt64Type
	case sema.UInt128Type:
		numericType = EncodedSemaNumericTypeUInt128Type
	case sema.UInt256Type:
		numericType = EncodedSemaNumericTypeUInt256Type
	case sema.Word8Type:
		numericType = EncodedSemaNumericTypeWord8Type
	case sema.Word16Type:
		numericType = EncodedSemaNumericTypeWord16Type
	case sema.Word32Type:
		numericType = EncodedSemaNumericTypeWord32Type
	case sema.Word64Type:
		numericType = EncodedSemaNumericTypeWord64Type
	case sema.FixedPointType:
		numericType = EncodedSemaNumericTypeFixedPointType
	case sema.SignedFixedPointType:
		numericType = EncodedSemaNumericTypeSignedFixedPointType
	default:
		return fmt.Errorf("unexpected numeric type: %s", t)
	}

	return e.write([]byte{byte(numericType)})
}

func (e *SemaEncoder) EncodeFixedPointNumericType(t *sema.FixedPointNumericType) (err error) {
	fixedPointNumericType := EncodedSemaUnknown

	switch t {
	case sema.Fix64Type:
		fixedPointNumericType = EncodedSemaFix64Type
	case sema.UFix64Type:
		fixedPointNumericType = EncodedSemaUFix64Type
	default:
		return fmt.Errorf("unexpected fixed point numeric type: %s", t)
	}

	return e.write([]byte{byte(fixedPointNumericType)})
}

func (e *SemaEncoder) EncodeBigInt(bi *big.Int) (err error) {
	sign := bi.Sign()
	neg := sign == -1
	err = e.EncodeBool(neg)
	if err != nil {
		return
	}

	return e.EncodeBytes(bi.Bytes())
}

func (e *SemaEncoder) EncodeTypeTag(tag sema.TypeTag) (err error) {
	err = e.EncodeUInt64(tag.UpperMask())
	if err != nil {
		return
	}

	return e.EncodeUInt64(tag.LowerMask())
}

func (e *SemaEncoder) EncodeTypeIdentifier(t sema.Type) (err error) {
	id := EncodedSemaUnknown

	switch concreteType := t.(type) {
	case *sema.SimpleType:
		return e.EncodeSimpleType(concreteType)
	case *sema.CompositeType:
		id = EncodedSemaCompositeType
	case *sema.InterfaceType:
		id = EncodedSemaInterfaceType
	case *sema.OptionalType:
		id = EncodedSemaOptionalType
	case *sema.GenericType:
		id = EncodedSemaGenericType
	case *sema.NumericType:
		return e.EncodeNumericType(concreteType)
	case *sema.FixedPointNumericType:
		return e.EncodeFixedPointNumericType(concreteType)
	case *sema.VariableSizedType:
		id = EncodedSemaVariableSizedType
	case *sema.ConstantSizedType:
		id = EncodedSemaConstantSizedType
	case *sema.FunctionType:
		id = EncodedSemaFunctionType
	case *sema.DictionaryType:
		id = EncodedSemaDictionaryType
	case *sema.ReferenceType:
		id = EncodedSemaReferenceType
	case *sema.AddressType:
		id = EncodedSemaAddressType
	case *sema.TransactionType:
		id = EncodedSemaTransactionType
	case *sema.RestrictedType:
		id = EncodedSemaRestrictedType
	case *sema.CapabilityType:
		id = EncodedSemaCapabilityType
	case nil:
		id = EncodedSemaNilType
	default:
		return fmt.Errorf("unexpected type: %s", concreteType)
	}

	// TODO remove
	if id == 0 {
		panic("type is zero somehow")
	}

	return e.write([]byte{byte(id)})
}

func (e *SemaEncoder) EncodePointer(bufferOffset int) (err error) {
	err = e.write([]byte{byte(EncodedSemaPointerType)})
	if err != nil {
		return
	}

	return e.EncodeLength(bufferOffset)
}

type EncodedSemaBuiltInCompositeType byte

const (
	EncodedSemaBuiltInCompositeTypeUnknown EncodedSemaBuiltInCompositeType = iota
	EncodedSemaBuiltInCompositeTypePublicAccountType
)

// TODO encode built-in CompositeTypes separately because they have unencodable values
//      (trying to avoid messing with CompositeType.nestedTypes)
// TODO are composite types encodable is CompositeType.IsStorable() is false?
// TODO if IsImportable is false then do we want to skip for execution state storage?
func (e *SemaEncoder) EncodeCompositeType(compositeType *sema.CompositeType) (err error) {
	// TODO must work with container types too
	//if compositeType.IsContainerType() {
	//	return fmt.Errorf("unexpected container type: %s", compositeType)
	//}

	// Location -> common.Location
	err = e.EncodeLocation(compositeType.Location)
	if err != nil {
		return
	}

	// Identifier -> string
	err = e.EncodeString(compositeType.Identifier)
	if err != nil {
		return
	}

	// Kind -> common.CompositeKind
	err = e.EncodeUInt64(uint64(compositeType.Kind))
	if err != nil {
		return
	}

	// ExplicitInterfaceConformances -> []*InterfaceType
	err = EncodeArray(e, compositeType.ExplicitInterfaceConformances, e.EncodeInterfaceType)
	if err != nil {
		return
	}

	// ImplicitTypeRequirementConformances -> []*CompositeType
	err = EncodeArray(e, compositeType.ImplicitTypeRequirementConformances, e.EncodeCompositeType)
	if err != nil {
		return
	}

	// Members -> *StringMemberOrderedMap
	err = e.EncodeStringMemberOrderedMap(compositeType.Members)
	if err != nil {
		return
	}

	// Fields -> []string
	err = EncodeArray(e, compositeType.Fields, e.EncodeString)
	if err != nil {
		return
	}

	// ConstructorParameters -> []*Parameter
	err = EncodeArray(e, compositeType.ConstructorParameters, e.EncodeParameter)
	if err != nil {
		return
	}

	// containerType -> Type
	err = e.EncodeType(compositeType.GetContainerType())
	if err != nil {
		return
	}

	// EnumRawType -> Type
	err = e.EncodeType(compositeType.EnumRawType)
	if err != nil {
		return
	}

	// hasComputedMembers -> bool
	err = e.EncodeBool(compositeType.HasComputedMembers())
	if err != nil {
		return
	}

	// ImportableWithoutLocation -> bool
	return e.EncodeBool(compositeType.ImportableWithoutLocation)
}

func (e *SemaEncoder) EncodeTypeParameter(p *sema.TypeParameter) (err error) {
	err = e.EncodeString(p.Name)
	if err != nil {
		return
	}

	err = e.EncodeType(p.TypeBound)
	if err != nil {
		return
	}

	return e.EncodeBool(p.Optional)
}

func (e *SemaEncoder) EncodeParameter(parameter *sema.Parameter) (err error) {
	err = e.EncodeString(parameter.Label)
	if err != nil {
		return
	}

	err = e.EncodeString(parameter.Identifier)
	if err != nil {
		return
	}

	return e.EncodeTypeAnnotation(parameter.TypeAnnotation)
}

func (e *SemaEncoder) EncodeStringMemberOrderedMap(om *sema.StringMemberOrderedMap) (err error) {
	if om == nil {
		return e.EncodeLength(0)
	}

	length := 0
	om.Foreach(func(key string, value *sema.Member) {
		if !value.IgnoreInSerialization {
			length++
		}
	})
	err = e.EncodeLength(length)
	if err != nil {
		return
	}

	return om.ForeachWithError(func(key string, value *sema.Member) error {
		if value.IgnoreInSerialization {
			return nil
		}

		err := e.EncodeString(key)
		if err != nil {
			return err
		}

		return e.EncodeMember(value)
	})
}

func (e *SemaEncoder) EncodeMember(member *sema.Member) (err error) {
	err = e.EncodeUInt64(uint64(member.Access))
	if err != nil {
		return
	}

	err = e.EncodeAstIdentifier(member.Identifier)
	if err != nil {
		return
	}

	err = e.EncodeTypeAnnotation(member.TypeAnnotation)
	if err != nil {
		return
	}

	err = e.EncodeUInt64(uint64(member.DeclarationKind))
	if err != nil {
		return
	}

	err = e.EncodeUInt64(uint64(member.VariableKind))
	if err != nil {
		return
	}

	err = EncodeArray(e, member.ArgumentLabels, e.EncodeString)
	if err != nil {
		return
	}

	err = e.EncodeBool(member.Predeclared)
	if err != nil {
		return
	}

	return e.EncodeString(member.DocString)
}

func (e *SemaEncoder) EncodeTypeAnnotation(anno *sema.TypeAnnotation) (err error) {
	err = e.EncodeBool(anno.IsResource)
	if err != nil {
		return
	}

	return e.EncodeType(anno.Type)
}

func (e *SemaEncoder) EncodeAstIdentifier(id ast.Identifier) (err error) {
	err = e.EncodeString(id.Identifier)
	if err != nil {
		return
	}

	return e.EncodeAstPosition(id.Pos)
}

func (e *SemaEncoder) EncodeAstPosition(pos ast.Position) (err error) {
	err = e.EncodeInt64(int64(pos.Offset))
	if err != nil {
		return
	}

	err = e.EncodeInt64(int64(pos.Line))
	if err != nil {
		return
	}

	return e.EncodeInt64(int64(pos.Column))
}

func (e *SemaEncoder) EncodeInterfaceType(interfaceType *sema.InterfaceType) (err error) {
	err = e.EncodeLocation(interfaceType.Location)
	if err != nil {
		return
	}

	err = e.EncodeString(interfaceType.Identifier)
	if err != nil {
		return
	}

	// TODO can this be guaranteed to be a single byte? or at least fewer than 8...
	err = e.EncodeUInt64(uint64(interfaceType.CompositeKind))
	if err != nil {
		return
	}

	err = e.EncodeStringMemberOrderedMap(interfaceType.Members)
	if err != nil {
		return
	}

	err = EncodeArray(e, interfaceType.Fields, e.EncodeString)
	if err != nil {
		return
	}

	err = EncodeArray(e, interfaceType.InitializerParameters, e.EncodeParameter)
	if err != nil {
		return
	}

	// TODO infinite recursion?
	err = e.EncodeType(interfaceType.GetContainerType())
	if err != nil {
		return
	}

	// TODO need to handle nested types? maybe same as composites: enums for built-ins?

	return
}

type EncodedBool byte

const (
	EncodedBoolUnknown EncodedBool = iota
	EncodedBoolFalse
	EncodedBoolTrue
)

func (e *SemaEncoder) EncodeBool(boolean bool) (err error) {
	b := EncodedBoolFalse
	if boolean {
		b = EncodedBoolTrue
	}

	return e.write([]byte{byte(b)})
}

// TODO use a more efficient encoder than `binary` (they say to in their top source comment)
func (e *SemaEncoder) EncodeUInt64(i uint64) (err error) {
	return binary.Write(&e.w, binary.BigEndian, i)
}

func (e *SemaEncoder) EncodeInt64(i int64) (err error) {
	return binary.Write(&e.w, binary.BigEndian, i)
}

func (e *SemaEncoder) EncodeLocation(location common.Location) (err error) {
	switch concreteType := location.(type) {
	case common.AddressLocation:
		return e.EncodeAddressLocation(concreteType)
	case common.IdentifierLocation:
		return e.EncodeIdentifierLocation(concreteType)
	case common.ScriptLocation:
		return e.EncodeScriptLocation(concreteType)
	case common.StringLocation:
		return e.EncodeStringLocation(concreteType)
	case common.TransactionLocation:
		return e.EncodeTransactionLocation(concreteType)
	case common.REPLLocation:
		return e.EncodeREPLLocation()
	case nil:
		return e.EncodeNilLocation()
	default:
		return fmt.Errorf("unexpected location type: %s", concreteType)
	}
}

// The location prefixes are stored as strings but are always* a single ascii character,
// so they can be stored in a single byte.
// * The exception is the REPL location but its first ascii character is unique anyway.
func (e *SemaEncoder) EncodeLocationPrefix(prefix string) (err error) {
	char := prefix[0]
	return e.write([]byte{char})
}

var NilLocationPrefix = "\x00"

// EncodeNilLocation encodes a value that indicates that no location is specified
func (e *SemaEncoder) EncodeNilLocation() (err error) {
	return e.EncodeLocationPrefix(NilLocationPrefix)
}

func (e *SemaEncoder) EncodeAddressLocation(t common.AddressLocation) (err error) {
	err = e.EncodeLocationPrefix(common.AddressLocationPrefix)
	if err != nil {
		return
	}

	err = e.EncodeAddress(t.Address)
	if err != nil {
		return
	}

	return e.EncodeString(t.Name)
}

func (e *SemaEncoder) EncodeIdentifierLocation(t common.IdentifierLocation) (err error) {
	err = e.EncodeLocationPrefix(common.IdentifierLocationPrefix)
	if err != nil {
		return
	}

	return e.EncodeString(string(t))
}

func (e *SemaEncoder) EncodeScriptLocation(t common.ScriptLocation) (err error) {
	err = e.EncodeLocationPrefix(common.ScriptLocationPrefix)
	if err != nil {
		return
	}

	return e.EncodeBytes(t)
}

func (e *SemaEncoder) EncodeStringLocation(t common.StringLocation) (err error) {
	err = e.EncodeLocationPrefix(common.StringLocationPrefix)
	if err != nil {
		return
	}

	return e.EncodeString(string(t))
}

func (e *SemaEncoder) EncodeTransactionLocation(t common.TransactionLocation) (err error) {
	err = e.EncodeLocationPrefix(common.TransactionLocationPrefix)
	if err != nil {
		return
	}

	return e.EncodeBytes(t)
}

func (e *SemaEncoder) EncodeREPLLocation() (err error) {
	return e.EncodeLocationPrefix(common.REPLLocationPrefix)
}

// EncodeString encodes a string as a byte array.
func (e *SemaEncoder) EncodeString(s string) (err error) {
	return e.EncodeBytes([]byte(s))
}

// EncodeBytes encodes a byte array.
func (e *SemaEncoder) EncodeBytes(bytes []byte) (err error) {
	err = e.EncodeLength(len(bytes))
	if err != nil {
		return
	}

	return e.write(bytes)
}

// TODO encode length with variable-sized encoding?
//      e.g. first byte starting with `0` is the last byte in the length
//      will usually save 3 bytes. the question is if it saves or costs encode and/or decode time

// EncodeLength encodes a non-negative length as a uint32.
// It uses 4 bytes.
func (e *SemaEncoder) EncodeLength(length int) (err error) {
	if length < 0 { // TODO is this safety check useful?
		return fmt.Errorf("cannot encode length below zero: %d", length)
	}

	// TODO is type conversion safe here?
	l := uint32(length)

	return binary.Write(&e.w, binary.BigEndian, l)
}

func (e *SemaEncoder) EncodeAddress(address common.Address) (err error) {
	return e.write(address[:])
}

func (e *SemaEncoder) write(b []byte) (err error) {
	_, err = e.w.Write(b)
	return
}

// TODO save a bit in the array length for nil check?

func EncodeArray[T any](e *SemaEncoder, arr []T, encodeFn func(T) error) (err error) {
	err = e.EncodeBool(arr == nil)
	if arr == nil || err != nil {
		return
	}

	err = e.EncodeLength(len(arr))
	if err != nil {
		return
	}

	for _, element := range arr {
		err = encodeFn(element)
		if err != nil {
			return
		}
	}

	return
}
