export interface User {
  id: string;
  username: string;
  balance: number;
}

export interface GameState {
  tableId: string;
  players: User[];
  dealer: string;
  status: "waiting" | "playing" | "finished";
}
