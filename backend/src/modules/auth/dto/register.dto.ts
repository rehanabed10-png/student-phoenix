import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Transform } from 'class-transformer';

export class RegisterDto {
  @IsNotEmpty({ message: 'Email is required.' })
  @IsEmail({}, { message: 'Invalid email address.' })
  @Transform(({ value }) => (typeof value === 'string' ? value.toLowerCase().trim() : value))
  email: string;

  @IsNotEmpty({ message: 'Password is required.' })
  @IsString({ message: 'Password must be a string.' })
  password: string;

  @IsNotEmpty({ message: 'First name is required.' })
  @IsString({ message: 'First name must be a string.' })
  @MinLength(1, { message: 'First name must be at least 1 character long.' })
  @MaxLength(50, { message: 'First name cannot exceed 50 characters.' })
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  firstName: string;

  @IsNotEmpty({ message: 'Last name is required.' })
  @IsString({ message: 'Last name must be a string.' })
  @MinLength(1, { message: 'Last name must be at least 1 character long.' })
  @MaxLength(50, { message: 'Last name cannot exceed 50 characters.' })
  @Transform(({ value }) => (typeof value === 'string' ? value.trim() : value))
  lastName: string;
}
