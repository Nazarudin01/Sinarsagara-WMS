import { Component, ErrorInfo, ReactNode } from 'react';
import { motion } from 'framer-motion';
import { styled } from 'styled-components';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

const ErrorContainer = styled(motion.div)`
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background-color: rgb(17, 24, 39);
`;

const ErrorCard = styled.div`
  max-width: 28rem;
  width: 100%;
  padding: 1.5rem;
  background-color: rgb(31, 41, 55);
  border-radius: 0.5rem;
  box-shadow: 0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1);
  border: 1px solid rgb(55, 65, 81);
`;

const ErrorTitle = styled.h2`
  font-size: 1.5rem;
  font-weight: 700;
  color: rgb(239, 68, 68);
  margin-bottom: 1rem;
  text-align: center;
`;

const ErrorMessage = styled.p`
  color: rgb(209, 213, 219);
  margin-bottom: 1.5rem;
  text-align: center;
`;

const RefreshButton = styled.button`
  padding: 0.5rem 1rem;
  background-color: rgb(16, 185, 129);
  color: white;
  border-radius: 0.5rem;
  transition: background-color 0.2s;

  &:hover {
    background-color: rgb(5, 150, 105);
  }
`;

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('Uncaught error:', error, errorInfo);
  }

  public render() {
    if (this.state.hasError) {
      return (
        <ErrorContainer
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.3 }}
        >
          <ErrorCard>
            <ErrorTitle>Oops! Something went wrong</ErrorTitle>
            <ErrorMessage>
              {this.state.error?.message || 'An unexpected error occurred'}
            </ErrorMessage>
            <div style={{ textAlign: 'center' }}>
              <RefreshButton onClick={() => window.location.reload()}>
                Refresh Page
              </RefreshButton>
            </div>
          </ErrorCard>
        </ErrorContainer>
      );
    }

    return this.props.children;
  }
} 