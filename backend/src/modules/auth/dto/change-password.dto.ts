import { IsNotEmpty, IsString } from 'class-validator';

export class ChangePasswordDto {
  @IsNotEmpty({ message: 'Current password is required.' })
  @IsString({ message: 'Current password must be a string.' })
  currentPassword: string;

  @IsNotEmpty({ message: 'New password is required.' })
  @IsString({ message: 'New password must be a string.' })
  newPassword: string;
}
