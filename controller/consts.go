package controller

const (
	IdtfUsername = 1
	IdtfEmail    = 2
	Binding      = 1
	Unbinding    = 2

	Success = 0

	InvalidToken     = 301
	LoginAgainNeeded = 302

	ParameterError          = 400
	InvalidUsername         = 401
	InvalidEmail            = 402
	InvalidPassword         = 403
	InvalidVerificationCode = 404
	InvalidIdentifierType   = 405
	InvalidScreenName       = 406
	ClaimNotMatchId         = 407

	InternalError   = 500
	DatabaseFailure = 501
	EmailFailure    = 502
)

var (
	SuccessResponse = BaseResponse{
		Message: "success",
		Code:    Success,
	}

	ParameterErrorResponse = BaseResponse{
		Message: "parameter error",
		Code:    ParameterError,
	}

	InvalidUsernameResponse = BaseResponse{
		Message: "invalid username",
		Code:    InvalidUsername,
	}

	InvalidEmailResponse = BaseResponse{
		Message: "invalid email",
		Code:    InvalidEmail,
	}

	InvalidPasswordResponse = BaseResponse{
		Message: "invalid password",
		Code:    InvalidPassword,
	}

	InvalidVerificationCodeResponse = BaseResponse{
		Message: "invalid verification code",
		Code:    InvalidVerificationCode,
	}

	InvalidIdentifierTypeResponse = BaseResponse{
		Message: "invalid identifier type",
		Code:    InvalidIdentifierType,
	}

	InvalidScreenNameResponse = BaseResponse{
		Message: "invalid screen name",
		Code:    InvalidScreenName,
	}

	ClaimNotMatchIdResponse = BaseResponse{
		Message: "claim does not match the id in request",
		Code:    ClaimNotMatchId,
	}
)
