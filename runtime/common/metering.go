/*
 * Cadence - The resource-oriented smart contract programming language
 *
 * Copyright 2022 Dapper Labs, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"math"
	"math/big"
	"unsafe"
)

type MemoryUsage struct {
	Kind   MemoryKind
	Amount uint64
}

type MemoryGauge interface {
	MeterMemory(usage MemoryUsage) error
}

var (
	ValueTokenMemoryUsage  = NewConstantMemoryUsage(MemoryKindValueToken)
	SyntaxTokenMemoryUsage = NewConstantMemoryUsage(MemoryKindSyntaxToken)
	SpaceTokenMemoryUsage  = NewConstantMemoryUsage(MemoryKindSpaceToken)

	ProgramMemoryUsage         = NewConstantMemoryUsage(MemoryKindProgram)
	IdentifierMemoryUsage      = NewConstantMemoryUsage(MemoryKindIdentifier)
	ArgumentMemoryUsage        = NewConstantMemoryUsage(MemoryKindArgument)
	BlockMemoryUsage           = NewConstantMemoryUsage(MemoryKindBlock)
	FunctionBlockMemoryUsage   = NewConstantMemoryUsage(MemoryKindFunctionBlock)
	ParameterMemoryUsage       = NewConstantMemoryUsage(MemoryKindParameter)
	ParameterListMemoryUsage   = NewConstantMemoryUsage(MemoryKindParameterList)
	TransferMemoryUsage        = NewConstantMemoryUsage(MemoryKindTransfer)
	TypeAnnotationMemoryUsage  = NewConstantMemoryUsage(MemoryKindTypeAnnotation)
	DictionaryEntryMemoryUsage = NewConstantMemoryUsage(MemoryKindDictionaryEntry)

	FunctionDeclarationMemoryUsage        = NewConstantMemoryUsage(MemoryKindFunctionDeclaration)
	CompositeDeclarationMemoryUsage       = NewConstantMemoryUsage(MemoryKindCompositeDeclaration)
	InterfaceDeclarationMemoryUsage       = NewConstantMemoryUsage(MemoryKindInterfaceDeclaration)
	ImportDeclarationMemoryUsage          = NewConstantMemoryUsage(MemoryKindImportDeclaration)
	TransactionDeclarationMemoryUsage     = NewConstantMemoryUsage(MemoryKindTransactionDeclaration)
	FieldDeclarationMemoryUsage           = NewConstantMemoryUsage(MemoryKindFieldDeclaration)
	EnumCaseDeclarationMemoryUsage        = NewConstantMemoryUsage(MemoryKindEnumCaseDeclaration)
	VariableDeclarationMemoryUsage        = NewConstantMemoryUsage(MemoryKindVariableDeclaration)
	SpecialFunctionDeclarationMemoryUsage = NewConstantMemoryUsage(MemoryKindSpecialFunctionDeclaration)
	PragmaDeclarationMemoryUsage          = NewConstantMemoryUsage(MemoryKindPragmaDeclaration)

	AssignmentStatementMemoryUsage = NewConstantMemoryUsage(MemoryKindAssignmentStatement)
	BreakStatementMemoryUsage      = NewConstantMemoryUsage(MemoryKindBreakStatement)
	ContinueStatementMemoryUsage   = NewConstantMemoryUsage(MemoryKindContinueStatement)
	EmitStatementMemoryUsage       = NewConstantMemoryUsage(MemoryKindEmitStatement)
	ExpressionStatementMemoryUsage = NewConstantMemoryUsage(MemoryKindExpressionStatement)
	ForStatementMemoryUsage        = NewConstantMemoryUsage(MemoryKindForStatement)
	IfStatementMemoryUsage         = NewConstantMemoryUsage(MemoryKindIfStatement)
	ReturnStatementMemoryUsage     = NewConstantMemoryUsage(MemoryKindReturnStatement)
	SwapStatementMemoryUsage       = NewConstantMemoryUsage(MemoryKindSwapStatement)
	SwitchStatementMemoryUsage     = NewConstantMemoryUsage(MemoryKindSwitchStatement)
	WhileStatementMemoryUsage      = NewConstantMemoryUsage(MemoryKindWhileStatement)

	BooleanExpressionMemoryUsage     = NewConstantMemoryUsage(MemoryKindBooleanExpression)
	NilExpressionMemoryUsage         = NewConstantMemoryUsage(MemoryKindNilExpression)
	StringExpressionMemoryUsage      = NewConstantMemoryUsage(MemoryKindStringExpression)
	IntegerExpressionMemoryUsage     = NewConstantMemoryUsage(MemoryKindIntegerExpression)
	FixedPointExpressionMemoryUsage  = NewConstantMemoryUsage(MemoryKindFixedPointExpression)
	IdentifierExpressionMemoryUsage  = NewConstantMemoryUsage(MemoryKindIdentifierExpression)
	InvocationExpressionMemoryUsage  = NewConstantMemoryUsage(MemoryKindInvocationExpression)
	MemberExpressionMemoryUsage      = NewConstantMemoryUsage(MemoryKindMemberExpression)
	IndexExpressionMemoryUsage       = NewConstantMemoryUsage(MemoryKindIndexExpression)
	ConditionalExpressionMemoryUsage = NewConstantMemoryUsage(MemoryKindConditionalExpression)
	UnaryExpressionMemoryUsage       = NewConstantMemoryUsage(MemoryKindUnaryExpression)
	BinaryExpressionMemoryUsage      = NewConstantMemoryUsage(MemoryKindBinaryExpression)
	FunctionExpressionMemoryUsage    = NewConstantMemoryUsage(MemoryKindFunctionExpression)
	CastingExpressionMemoryUsage     = NewConstantMemoryUsage(MemoryKindCastingExpression)
	CreateExpressionMemoryUsage      = NewConstantMemoryUsage(MemoryKindCreateExpression)
	DestroyExpressionMemoryUsage     = NewConstantMemoryUsage(MemoryKindDestroyExpression)
	ReferenceExpressionMemoryUsage   = NewConstantMemoryUsage(MemoryKindReferenceExpression)
	ForceExpressionMemoryUsage       = NewConstantMemoryUsage(MemoryKindForceExpression)
	PathExpressionMemoryUsage        = NewConstantMemoryUsage(MemoryKindPathExpression)

	ConstantSizedTypeMemoryUsage = NewConstantMemoryUsage(MemoryKindConstantSizedType)
	DictionaryTypeMemoryUsage    = NewConstantMemoryUsage(MemoryKindDictionaryType)
	FunctionTypeMemoryUsage      = NewConstantMemoryUsage(MemoryKindFunctionType)
	InstantiationTypeMemoryUsage = NewConstantMemoryUsage(MemoryKindInstantiationType)
	NominalTypeMemoryUsage       = NewConstantMemoryUsage(MemoryKindNominalType)
	OptionalTypeMemoryUsage      = NewConstantMemoryUsage(MemoryKindOptionalType)
	ReferenceTypeMemoryUsage     = NewConstantMemoryUsage(MemoryKindReferenceType)
	RestrictedTypeMemoryUsage    = NewConstantMemoryUsage(MemoryKindRestrictedType)
	VariableSizedTypeMemoryUsage = NewConstantMemoryUsage(MemoryKindVariableSizedType)

	PositionMemoryUsage = NewConstantMemoryUsage(MemoryKindPosition)
	RangeMemoryUsage    = NewConstantMemoryUsage(MemoryKindRange)

	ElaborationMemoryUsage = NewConstantMemoryUsage(MemoryKindElaboration)
)

func UseMemory(gauge MemoryGauge, usage MemoryUsage) {
	if gauge == nil {
		return
	}

	err := gauge.MeterMemory(usage)
	if err != nil {
		panic(err)
	}
}

func NewConstantMemoryUsage(kind MemoryKind) MemoryUsage {
	return MemoryUsage{
		Kind:   kind,
		Amount: 1,
	}
}

func NewArrayMemoryUsages(length int) (MemoryUsage, MemoryUsage) {
	return MemoryUsage{
			Kind:   MemoryKindArrayBase,
			Amount: 1,
		}, MemoryUsage{
			Kind:   MemoryKindArrayLength,
			Amount: uint64(length),
		}
}

func NewArrayAdditionalLengthUsage(originalLength, additionalLength int) MemoryUsage {
	var newAmount uint64
	if originalLength <= 1 {
		newAmount = uint64(originalLength + additionalLength)
	} else {
		// size of b+ tree grows logarithmically with the size of the tree
		newAmount = uint64(math.Log2(float64(originalLength)) + float64(additionalLength))
	}
	return MemoryUsage{
		Kind:   MemoryKindArrayLength,
		Amount: newAmount,
	}
}

func NewDictionaryMemoryUsages(length int) (MemoryUsage, MemoryUsage) {
	return MemoryUsage{
			Kind:   MemoryKindDictionaryBase,
			Amount: 1,
		}, MemoryUsage{
			Kind:   MemoryKindDictionarySize,
			Amount: uint64(length),
		}
}

func NewDictionaryAdditionalSizeUsage(originalSize, additionalSize int) MemoryUsage {
	var newAmount uint64
	if originalSize <= 1 {
		newAmount = uint64(originalSize + additionalSize)
	} else {
		// size of b+ tree grows logarithmically with the size of the tree
		newAmount = uint64(math.Log2(float64(originalSize)) + float64(additionalSize))
	}
	return MemoryUsage{
		Kind:   MemoryKindDictionarySize,
		Amount: newAmount,
	}
}

func NewCompositeMemoryUsages(length int) (MemoryUsage, MemoryUsage) {
	return MemoryUsage{
			Kind:   MemoryKindCompositeBase,
			Amount: 1,
		}, MemoryUsage{
			Kind:   MemoryKindCompositeSize,
			Amount: uint64(length),
		}
}

func NewStringMemoryUsage(length int) MemoryUsage {
	return MemoryUsage{
		Kind:   MemoryKindString,
		Amount: uint64(length) + 1, // +1 to account for empty strings
	}
}

func NewRawStringMemoryUsage(length int) MemoryUsage {
	return MemoryUsage{
		Kind:   MemoryKindRawString,
		Amount: uint64(length) + 1, // +1 to account for empty strings
	}
}

func NewBytesMemoryUsage(length int) MemoryUsage {
	return MemoryUsage{
		Kind:   MemoryKindBytes,
		Amount: uint64(length) + 1, // +1 to account for empty arrays
	}
}

func NewBigIntMemoryUsage(bytes int) MemoryUsage {
	return MemoryUsage{
		Kind:   MemoryKindBigInt,
		Amount: uint64(bytes),
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

const bigIntWordSize = int(unsafe.Sizeof(big.Word(0)))

func BigIntByteLength(v *big.Int) int {
	// NOTE: big.Int.Bits() actually returns bytes:
	// []big.Word, where big.Word = uint
	return len(v.Bits()) * bigIntWordSize
}

func NewPlusBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		max(
			BigIntByteLength(a),
			BigIntByteLength(b),
		) + bigIntWordSize,
	)
}

func NewMinusBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		max(
			BigIntByteLength(a),
			BigIntByteLength(b),
		),
	)
}

func NewMulBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		BigIntByteLength(a) +
			BigIntByteLength(b),
	)
}

func NewTypeMemoryUsage(staticTypeAsString string) MemoryUsage {
	return MemoryUsage{
		Kind:   MemoryKindTypeValue,
		Amount: uint64(len(staticTypeAsString)),
	}
}

func NewCharacterMemoryUsage(length int) MemoryUsage {
	return MemoryUsage{
		Kind:   MemoryKindCharacter,
		Amount: uint64(length),
	}
}

func NewModBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		max(
			BigIntByteLength(a),
			BigIntByteLength(b),
		),
	)
}

func NewDivBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		max(
			BigIntByteLength(a),
			BigIntByteLength(b),
		),
	)
}

func NewBitwiseOrBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		max(
			BigIntByteLength(a),
			BigIntByteLength(b),
		),
	)
}

func NewBitwiseXorBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		max(
			BigIntByteLength(a),
			BigIntByteLength(b),
		),
	)
}

func NewBitwiseAndBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		max(
			BigIntByteLength(a),
			BigIntByteLength(b),
		),
	)
}

func NewBitwiseLeftShiftBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		BigIntByteLength(a) +
			BigIntByteLength(b),
	)
}

func NewBitwiseRightShiftBigIntMemoryUsage(a, b *big.Int) MemoryUsage {
	return NewBigIntMemoryUsage(
		// TODO: https://github.com/dapperlabs/cadence-private-issues/issues/32
		max(
			BigIntByteLength(a),
			BigIntByteLength(b),
		),
	)
}

func NewNumberMemoryUsage(bytes int) MemoryUsage {
	return MemoryUsage{
		Kind:   MemoryKindNumber,
		Amount: uint64(bytes),
	}
}

func NewArrayExpressionMemoryUsage(length int) MemoryUsage {
	return MemoryUsage{
		Kind: MemoryKindArrayExpression,
		// +1 to account for empty arrays
		Amount: uint64(length) + 1,
	}
}

func NewDictionaryExpressionMemoryUsage(length int) MemoryUsage {
	return MemoryUsage{
		Kind: MemoryKindDictionaryExpression,
		// +1 to account for empty dictionaries
		Amount: uint64(length) + 1,
	}
}
func NewMembersMemoryUsage(length int) MemoryUsage {
	return MemoryUsage{
		Kind: MemoryKindMembers,
		// +1 to account for empty members
		Amount: uint64(length) + 1,
	}
}

// UseConstantMemory uses a pre-determined amount of memory
//
func UseConstantMemory(memoryGauge MemoryGauge, kind MemoryKind) {
	UseMemory(memoryGauge, MemoryUsage{
		Kind:   kind,
		Amount: 1,
	})
}
