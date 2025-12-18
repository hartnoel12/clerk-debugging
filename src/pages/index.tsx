import { SignInButton, SignOutButton, useUser, useAuth } from '@clerk/nextjs';
import { useState } from 'react';

export default function Home() {
  const { isSignedIn, user, isLoaded } = useUser();
  const { signOut } = useAuth();
  const [apiResponse, setApiResponse] = useState<any>(null);
  const [apiLoading, setApiLoading] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);

  const testApi = async () => {
    setApiLoading(true);
    setApiError(null);
    setApiResponse(null);
    
    try {
      const res = await fetch('/api/test');
      const data = await res.json();
      
      if (!res.ok) {
        setApiError(data.error || 'API request failed');
        setApiResponse(data);
      } else {
        setApiResponse(data);
      }
    } catch (error) {
      setApiError(error instanceof Error ? error.message : 'Unknown error');
    } finally {
      setApiLoading(false);
    }
  };

  // Show loading state while Clerk is initializing
  if (!isLoaded) {
    return (
      <div style={{ padding: '2rem', textAlign: 'center' }}>
        <h1>Clerk Authentication Test</h1>
        <p>Loading...</p>
      </div>
    );
  }

  return (
    <div style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <h1>Clerk Authentication Test</h1>
      
      {isSignedIn ? (
        <div>
          <div style={{ 
            padding: '1rem', 
            backgroundColor: '#f0f0f0', 
            borderRadius: '8px',
            marginBottom: '1rem'
          }}>
            <h2>User Information</h2>
            <p><strong>Email:</strong> {user?.primaryEmailAddress?.emailAddress}</p>
            <p><strong>User ID:</strong> {user?.id}</p>
            <p><strong>First Name:</strong> {user?.firstName || 'N/A'}</p>
            <p><strong>Last Name:</strong> {user?.lastName || 'N/A'}</p>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <SignOutButton>
              <button style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#dc3545',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer'
              }}>
                Sign Out
              </button>
            </SignOutButton>
          </div>

          <hr style={{ margin: '2rem 0' }} />

          <div>
            <h2>API Test</h2>
            <p>Test the authenticated API endpoint:</p>
            <button 
              onClick={testApi}
              disabled={apiLoading}
              style={{
                padding: '0.5rem 1rem',
                backgroundColor: '#007bff',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: apiLoading ? 'not-allowed' : 'pointer',
                opacity: apiLoading ? 0.6 : 1,
                marginBottom: '1rem'
              }}
            >
              {apiLoading ? 'Testing...' : 'Test API Route'}
            </button>

            {apiError && (
              <div style={{
                padding: '1rem',
                backgroundColor: '#f8d7da',
                color: '#721c24',
                borderRadius: '4px',
                marginBottom: '1rem'
              }}>
                <strong>Error:</strong> {apiError}
              </div>
            )}

            {apiResponse && (
              <div style={{
                padding: '1rem',
                backgroundColor: '#d4edda',
                color: '#155724',
                borderRadius: '4px',
                marginTop: '1rem'
              }}>
                <h3>API Response:</h3>
                <pre style={{ 
                  backgroundColor: '#f8f9fa',
                  padding: '1rem',
                  borderRadius: '4px',
                  overflow: 'auto'
                }}>
                  {JSON.stringify(apiResponse, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      ) : (
        <div style={{ textAlign: 'center' }}>
          <p style={{ fontSize: '1.2rem', marginBottom: '2rem' }}>
            You are not signed in. Please sign in to continue.
          </p>
          <SignInButton mode="modal">
            <button style={{
              padding: '0.75rem 1.5rem',
              backgroundColor: '#007bff',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '1rem'
            }}>
              Sign In
            </button>
          </SignInButton>
        </div>
      )}
    </div>
  );
}