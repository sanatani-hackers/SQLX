from typing import Callable, Dict, List, Any
import threading

class EventBus:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(EventBus, cls).__new__(cls)
                cls._instance._subscribers = {}
        return cls._instance
        
    def subscribe(self, event_name: str, callback: Callable[[Any], None]):
        if event_name not in self._subscribers:
            self._subscribers[event_name] = []
        if callback not in self._subscribers[event_name]:
            self._subscribers[event_name].append(callback)
            
    def unsubscribe(self, event_name: str, callback: Callable[[Any], None]):
        if event_name in self._subscribers:
            if callback in self._subscribers[event_name]:
                self._subscribers[event_name].remove(callback)
                
    def publish(self, event_name: str, data: Any = None):
        if event_name in self._subscribers:
            for callback in self._subscribers[event_name]:
                try:
                    callback(data)
                except Exception as e:
                    print(f"Error in event handler for {event_name}: {e}")

# Global singleton instance
bus = EventBus()
