import { render, screen, fireEvent } from '@testing-library/react';
import { GamingButton } from '@/components/ui/gaming-button';

describe('GamingButton', () => {
  it('renders correctly', () => {
    render(<GamingButton>Click me</GamingButton>);
    expect(screen.getByText('Click me')).toBeInTheDocument();
  });

  it('handles click events', () => {
    const handleClick = jest.fn();
    render(<GamingButton onClick={handleClick}>Click me</GamingButton>);
    fireEvent.click(screen.getByText('Click me'));
    expect(handleClick).toHaveBeenCalledTimes(1);
  });

  it('shows loading state', () => {
    render(<GamingButton loading>Click me</GamingButton>);
    expect(screen.getByRole('button')).toBeDisabled();
    expect(screen.getByRole('button')).toHaveClass('opacity-70');
  });

  it('applies variant styles', () => {
    const { rerender } = render(<GamingButton variant="primary">Click me</GamingButton>);
    expect(screen.getByRole('button')).toHaveClass('from-blue-500');

    rerender(<GamingButton variant="secondary">Click me</GamingButton>);
    expect(screen.getByRole('button')).toHaveClass('bg-gray-800');

    rerender(<GamingButton variant="danger">Click me</GamingButton>);
    expect(screen.getByRole('button')).toHaveClass('from-red-500');

    rerender(<GamingButton variant="success">Click me</GamingButton>);
    expect(screen.getByRole('button')).toHaveClass('from-green-500');
  });

  it('applies size styles', () => {
    const { rerender } = render(<GamingButton size="sm">Click me</GamingButton>);
    expect(screen.getByRole('button')).toHaveClass('text-sm');

    rerender(<GamingButton size="md">Click me</GamingButton>);
    expect(screen.getByRole('button')).toHaveClass('text-base');

    rerender(<GamingButton size="lg">Click me</GamingButton>);
    expect(screen.getByRole('button')).toHaveClass('text-lg');
  });
}); 