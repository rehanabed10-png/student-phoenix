import type { UserResponseDto } from '../../users/dto/user-response.dto.js';

export class AuthResponseDto {
  accessToken: string;
  user: UserResponseDto;
}
