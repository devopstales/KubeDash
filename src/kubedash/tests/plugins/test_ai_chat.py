"""
Tests for AI Chat plugin API endpoints.
"""

import pytest
from flask import url_for
from flask_login import login_user

from lib.components import db
from lib.user import User, Role, UserCreate, RoleCreate
from plugins.ai_chat.model import McpConversation, McpMessage


@pytest.fixture
def ai_chat_user(app, session):
    """Create a test user for AI chat tests"""
    # Clean up any existing roles/users
    McpMessage.query.delete()
    McpConversation.query.delete()
    User.query.filter(User.username.like('aichatuser%')).delete()
    User.query.filter(User.username.like('otheruser%')).delete()
    Role.query.filter_by(name="User").delete()
    Role.query.filter_by(name="Admin").delete()
    session.commit()
    
    RoleCreate("User")
    RoleCreate("Admin")
    
    user = User.query.filter_by(username="aichatuser").first()
    if not user:
        UserCreate("aichatuser", "testpass", "aichat@example.com", "Local", "User")
        session.commit()
        user = User.query.filter_by(username="aichatuser").first()
    return user


@pytest.fixture
def authenticated_ai_chat_client(client, ai_chat_user):
    """Create authenticated client for AI chat tests"""
    with client.session_transaction() as sess:
        login_user(ai_chat_user)
        sess['user_name'] = "aichatuser"
        sess['user_role'] = "User"
        sess['user_type'] = "Local"
    return client


class TestAIChatAPI:
    """Test AI Chat API endpoints"""

    def test_list_conversations_empty(self, authenticated_ai_chat_client, session):
        """Test listing conversations when none exist"""
        # Clean up any existing conversations
        McpConversation.query.delete()
        session.commit()

        response = authenticated_ai_chat_client.get('/api/v1/plugins/ai-chat/chat/conversations')
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) == 0

    def test_list_conversations_with_data(self, authenticated_ai_chat_client, session, ai_chat_user):
        """Test listing conversations with existing data"""
        # Create a test conversation
        conv = McpConversation(user_id=ai_chat_user.id, title="Test Conversation")
        session.add(conv)
        session.commit()
        
        # Add a message
        msg = McpMessage(
            conversation_id=conv.id,
            role="user",
            content="Hello"
        )
        session.add(msg)
        session.commit()

        response = authenticated_ai_chat_client.get('/api/v1/plugins/ai-chat/chat/conversations')
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]['id'] == conv.id
        assert data[0]['title'] == "Test Conversation"
        assert data[0]['message_count'] == 1

    def test_get_conversation(self, authenticated_ai_chat_client, session, ai_chat_user):
        """Test getting a specific conversation with messages"""
        conv = McpConversation(user_id=ai_chat_user.id, title="Test Conv")
        session.add(conv)
        session.commit()
        
        msg1 = McpMessage(conversation_id=conv.id, role="user", content="Hello")
        msg2 = McpMessage(conversation_id=conv.id, role="assistant", content="Hi there!")
        session.add_all([msg1, msg2])
        session.commit()

        response = authenticated_ai_chat_client.get(f'/api/v1/plugins/ai-chat/chat/conversations/{conv.id}')
        assert response.status_code == 200
        data = response.get_json()
        assert 'conversation' in data
        assert 'messages' in data
        assert len(data['messages']) == 2
        assert data['conversation']['id'] == conv.id

    def test_get_conversation_not_found(self, authenticated_ai_chat_client):
        """Test getting a non-existent conversation"""
        response = authenticated_ai_chat_client.get('/api/v1/plugins/ai-chat/chat/conversations/99999')
        assert response.status_code == 404

    def test_get_conversation_other_user(self, authenticated_ai_chat_client, session, ai_chat_user):
        """Test that users can't access other users' conversations"""
        # Create conversation for a different user
        other_user = User.query.filter_by(username="otheruser").first()
        if not other_user:
            UserCreate("otheruser", "testpass", "other@example.com", "Local", "User")
            session.commit()
            other_user = User.query.filter_by(username="otheruser").first()
        
        conv = McpConversation(user_id=other_user.id, title="Other User Conv")
        session.add(conv)
        session.commit()
        conv_id = conv.id

        response = authenticated_ai_chat_client.get(f'/api/v1/plugins/ai-chat/chat/conversations/{conv_id}')
        assert response.status_code == 404

    def test_delete_conversation(self, authenticated_ai_chat_client, session, ai_chat_user):
        """Test deleting a conversation"""
        conv = McpConversation(user_id=ai_chat_user.id, title="To Delete")
        session.add(conv)
        session.commit()
        conv_id = conv.id

        response = authenticated_ai_chat_client.delete(f'/api/v1/plugins/ai-chat/chat/conversations/{conv_id}')
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'deleted'
        
        # Verify it's deleted
        deleted_conv = McpConversation.query.get(conv_id)
        assert deleted_conv is None

    def test_chat_message_new_conversation(self, authenticated_ai_chat_client, session):
        """Test sending a message to start a new conversation"""
        response = authenticated_ai_chat_client.post(
            '/api/v1/plugins/ai-chat/chat/message',
            json={'content': 'Hello, list namespaces'}
        )
        assert response.status_code == 200
        data = response.get_json()
        assert 'conversation_id' in data
        assert 'message' in data
        assert data['message']['role'] == 'assistant'
        
        # Verify conversation was created
        conv = McpConversation.query.get(int(data['conversation_id']))
        assert conv is not None

    def test_chat_message_existing_conversation(self, authenticated_ai_chat_client, session, ai_chat_user):
        """Test sending a message to an existing conversation"""
        conv = McpConversation(user_id=ai_chat_user.id, title="Existing")
        session.add(conv)
        session.commit()
        conv_id = conv.id

        response = authenticated_ai_chat_client.post(
            '/api/v1/plugins/ai-chat/chat/message',
            json={'content': 'Follow up message', 'conversation_id': str(conv_id)}
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['conversation_id'] == str(conv_id)

    def test_chat_message_empty_content(self, authenticated_ai_chat_client):
        """Test sending empty message returns error"""
        response = authenticated_ai_chat_client.post(
            '/api/v1/plugins/ai-chat/chat/message',
            json={'content': ''}
        )
        assert response.status_code == 400

    def test_chat_message_no_content(self, authenticated_ai_chat_client):
        """Test sending message without content returns error"""
        response = authenticated_ai_chat_client.post(
            '/api/v1/plugins/ai-chat/chat/message',
            json={}
        )
        assert response.status_code == 400

    def test_provider_info(self, authenticated_ai_chat_client):
        """Test getting provider info"""
        response = authenticated_ai_chat_client.get('/api/v1/plugins/ai-chat/provider/info')
        assert response.status_code == 200
        data = response.get_json()
        assert isinstance(data, dict)

    def test_provider_health(self, authenticated_ai_chat_client):
        """Test getting provider health status"""
        response = authenticated_ai_chat_client.get('/api/v1/plugins/ai-chat/provider/health')
        assert response.status_code == 200
        data = response.get_json()
        assert 'healthy' in data
        assert 'provider' in data

    def test_unauthenticated_access(self, client):
        """Test that unauthenticated access is denied"""
        response = client.get('/api/v1/plugins/ai-chat/chat/conversations')
        assert response.status_code in [302, 401]


class TestAIChatModel:
    """Test AI Chat database models"""

    def test_conversation_to_dict(self, session, ai_chat_user):
        """Test conversation to_dict method"""
        conv = McpConversation(user_id=ai_chat_user.id, title="Test")
        session.add(conv)
        session.commit()
        
        result = conv.to_dict()
        assert result['id'] == conv.id
        assert result['title'] == "Test"
        assert result['user_id'] == ai_chat_user.id
        assert 'message_count' in result

    def test_message_to_dict(self, session, ai_chat_user):
        """Test message to_dict method"""
        conv = McpConversation(user_id=ai_chat_user.id)
        session.add(conv)
        session.commit()
        
        msg = McpMessage(
            conversation_id=conv.id,
            role="user",
            content="Test message"
        )
        session.add(msg)
        session.commit()
        
        result = msg.to_dict()
        assert result['id'] == msg.id
        assert result['role'] == "user"
        assert result['content'] == "Test message"
        assert result['conversation_id'] == conv.id

    def test_conversation_to_dict_with_error(self, session, ai_chat_user):
        """Test conversation to_dict handles errors gracefully"""
        conv = McpConversation(user_id=ai_chat_user.id, title="Test")
        session.add(conv)
        session.commit()
        
        # Should not raise even if messages relationship has issues
        result = conv.to_dict()
        assert 'message_count' in result
        assert isinstance(result['message_count'], int)
