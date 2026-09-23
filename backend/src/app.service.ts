import { Injectable } from '@nestjs/common';

export interface HealthCheckResponse {
  status: string;
  service: string;
}

@Injectable()
export class AppService {
  getHealth(): HealthCheckResponse {
    return {
      status: 'ok',
      service: 'student-phoenix-api',
    };
  }
}
