import { IsEmail, IsString, IsOptional, IsBoolean, MinLength, Matches } from 'class-validator';

export class LoginDto {
  @IsEmail({}, { message: 'Email không hợp lệ' })
  email: string;

  @IsOptional()
  @IsString()
  @MinLength(8, { message: 'Mật khẩu tối thiểu 8 ký tự' })
  password?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\d{6}$/, { message: 'OTP phải có 6 chữ số' })
  otp?: string;

  @IsOptional()
  @IsString()
  deviceFingerprint?: string;

  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean;
}

export class SendOtpDto {
  @IsEmail({}, { message: 'Email không hợp lệ' })
  @Matches(/@(miichisoft\.com|miichisoft\.net)$/, {
    message: 'Chỉ chấp nhận email @miichisoft.com hoặc @miichisoft.net'
  })
  email: string;
}

export class VerifyOtpDto {
  @IsEmail({}, { message: 'Email không hợp lệ' })
  email: string;

  @IsString()
  @Matches(/^\d{6}$/, { message: 'OTP phải có 6 chữ số' })
  otp: string;

  @IsOptional()
  @IsString()
  deviceFingerprint?: string;

  @IsOptional()
  @IsBoolean()
  rememberMe?: boolean;
}

export class CreateUserDto {
  @IsEmail({}, { message: 'Email không hợp lệ' })
  email: string;

  @IsString()
  @MinLength(3, { message: 'Username tối thiểu 3 ký tự' })
  username: string;

  @IsString()
  @MinLength(8, { message: 'Mật khẩu tối thiểu 8 ký tự' })
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message: 'Mật khẩu phải chứa chữ hoa, chữ thường, số và ký tự đặc biệt'
  })
  password: string;

  @IsOptional()
  @IsString()
  firstName?: string;

  @IsOptional()
  @IsString()
  lastName?: string;
}
