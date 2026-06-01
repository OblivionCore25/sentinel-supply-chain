import { useEffect, useState, useCallback } from 'react';
import { wsService } from '../services/websocket';
import type { WebSocketMessage } from '../services/websocket';
import type { RiskScore, Alert } from '../services/api';

/**
 * Hook to manage WebSocket connection and receive real-time events.
 */
export function useWebSocket() {
  const [isConnected, setIsConnected] = useState(wsService.isConnected);
  const [riskScores, setRiskScores] = useState<RiskScore[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [lastEvent, setLastEvent] = useState<WebSocketMessage | null>(null);

  useEffect(() => {
    wsService.connect();

    const unsubConnection = wsService.onConnectionChange(setIsConnected);

    const unsubMessages = wsService.subscribe((message) => {
      setLastEvent(message);

      switch (message.type) {
        case 'RISK_SCORE':
          setRiskScores((prev) => [message.payload as RiskScore, ...prev].slice(0, 50));
          break;
        case 'ALERT':
          setAlerts((prev) => [message.payload as Alert, ...prev].slice(0, 50));
          break;
      }
    });

    return () => {
      unsubConnection();
      unsubMessages();
    };
  }, []);

  return { isConnected, riskScores, alerts, lastEvent };
}

/**
 * Hook to fetch data with loading and error states.
 */
export function useFetch<T>(fetcher: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refetch = useCallback(() => {
    setLoading(true);
    setError(null);
    fetcher()
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, deps);

  useEffect(() => {
    refetch();
  }, [refetch]);

  return { data, loading, error, refetch };
}
