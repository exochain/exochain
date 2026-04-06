//! Tiered notification system with fatigue controls (UX-005).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Notification delivery channel.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum NotificationChannel {
    InApp,
    Email,
    Sms,
    Webhook,
    Slack,
}

/// Notification priority tier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum NotificationPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// A notification to be delivered.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub id: Uuid,
    pub tenant_id: String,
    pub recipient: String,
    pub title: String,
    pub body: String,
    pub priority: NotificationPriority,
    pub channels: Vec<NotificationChannel>,
    pub created_at: DateTime<Utc>,
    pub delivered: bool,
    pub read: bool,
}

/// Notification service with fatigue controls.
pub struct NotificationService {
    notifications: Vec<Notification>,
    max_per_hour: u32,
}

impl NotificationService {
    /// Create a new notification service with the given per-recipient hourly limit.
    pub fn new(max_per_hour: u32) -> Self {
        Self {
            notifications: Vec::new(),
            max_per_hour,
        }
    }

    /// Send a notification, respecting fatigue controls.
    #[allow(clippy::expect_used)] // Safety: vec.last() after vec.push() is always Some.
    pub fn send(
        &mut self,
        tenant_id: String,
        recipient: String,
        title: String,
        body: String,
        priority: NotificationPriority,
        channels: Vec<NotificationChannel>,
    ) -> Result<&Notification, NotificationError> {
        // Fatigue control: check recent notification count for this recipient
        let recent_count = self.recent_count(&recipient);
        if recent_count >= self.max_per_hour && priority < NotificationPriority::Critical {
            return Err(NotificationError::FatigueLimitReached {
                recipient,
                count: recent_count,
            });
        }

        let notification = Notification {
            id: Uuid::new_v4(),
            tenant_id,
            recipient,
            title,
            body,
            priority,
            channels,
            created_at: Utc::now(),
            delivered: true,
            read: false,
        };

        self.notifications.push(notification);
        // Safety: we just pushed, so last() is always Some
        Ok(self
            .notifications
            .last()
            .expect("just pushed, vec is non-empty"))
    }

    /// Count recent notifications for a recipient (within the last hour).
    fn recent_count(&self, recipient: &str) -> u32 {
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        self.notifications
            .iter()
            .filter(|n| n.recipient == recipient && n.created_at > one_hour_ago)
            .count() as u32
    }

    /// Get unread notifications for a recipient.
    pub fn unread(&self, recipient: &str) -> Vec<&Notification> {
        self.notifications
            .iter()
            .filter(|n| n.recipient == recipient && !n.read)
            .collect()
    }

    /// Mark a notification as read.
    pub fn mark_read(&mut self, id: Uuid) -> bool {
        if let Some(n) = self.notifications.iter_mut().find(|n| n.id == id) {
            n.read = true;
            true
        } else {
            false
        }
    }
}

/// Notification errors.
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("Notification fatigue limit reached for {recipient}: {count} notifications in the last hour")]
    FatigueLimitReached { recipient: String, count: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_notification() {
        let mut svc = NotificationService::new(100);
        let result = svc.send(
            "tenant-1".into(),
            "did:exo:alice".into(),
            "Vote Required".into(),
            "Decision D-001 needs your vote".into(),
            NotificationPriority::High,
            vec![NotificationChannel::InApp, NotificationChannel::Email],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_fatigue_control() {
        let mut svc = NotificationService::new(2);

        for i in 0..2 {
            svc.send(
                "t1".into(),
                "alice".into(),
                format!("Title {}", i),
                "body".into(),
                NotificationPriority::Low,
                vec![NotificationChannel::InApp],
            )
            .unwrap();
        }

        // Third low-priority notification should be blocked
        let result = svc.send(
            "t1".into(),
            "alice".into(),
            "Title 3".into(),
            "body".into(),
            NotificationPriority::Low,
            vec![NotificationChannel::InApp],
        );
        assert!(result.is_err());

        // Critical notifications bypass fatigue control
        let result = svc.send(
            "t1".into(),
            "alice".into(),
            "EMERGENCY".into(),
            "critical".into(),
            NotificationPriority::Critical,
            vec![NotificationChannel::InApp],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_unread_and_mark_read() {
        let mut svc = NotificationService::new(100);
        svc.send(
            "t1".into(),
            "alice".into(),
            "Test".into(),
            "body".into(),
            NotificationPriority::Medium,
            vec![NotificationChannel::InApp],
        )
        .unwrap();

        let unread = svc.unread("alice");
        assert_eq!(unread.len(), 1);
        let id = unread[0].id;

        svc.mark_read(id);
        assert!(svc.unread("alice").is_empty());
    }
}
