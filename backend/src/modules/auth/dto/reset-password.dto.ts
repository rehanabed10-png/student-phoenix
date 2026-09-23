import { IsNotEmpty, IsString } from 'class-validator';

export class ResetPasswordDto {
  @IsNotEmpty({ message: 'Reset token is required.' })
  @IsString({ message: 'Reset token must be a string.' })
  token: string;

  @IsNotEmpty({ message: 'New password is required.' })
  @IsString({ message: 'New password must be a string.' })
  newPassword: string;
}
