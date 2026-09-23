/**
 * Global TypeScript types and interfaces for the Student Phoenix platform.
 */
export interface ApiResponse<T = unknown> {
  status: string;
  data?: T;
  message?: string;
}
