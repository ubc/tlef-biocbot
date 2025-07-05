/** @type {import('next').NextConfig} */
const nextConfig = {
    async rewrites() {
        return [
            {
                source: '/api/:path*',
                destination: 'http://localhost:7736/api/:path*', // Proxy to Backend
            },
        ];
    },
};

export default nextConfig;
