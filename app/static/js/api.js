// Centralized API call function
async function apiCall(endpoint, method = 'GET', body = null, headers = {}) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
            ...headers,
        },
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    try {
        const response = await fetch(`${endpoint}`, options);

        if (!response.ok) {
            const errorData = await response.json();
            const errorMessage = errorData.error || 'An unknown error occurred';
            throw new Error(errorMessage);
        }

        const data = await response.json();
        return data;

    } catch (error) {
        console.error('API call error:', error);
        throw error;
    }
}

export const api = {
    addAuthentication: (authData) => apiCall('/auth/set-credentials', 'POST', authData),
    createAccessToken: () => apiCall('/auth/create-access-token'),
    deleteAccessToken: () => apiCall('/auth/delete-access-token', 'DELETE'),

    login: (loginData) => apiCall('/auth/login', 'POST', loginData),
    register: (registerData) => apiCall('/auth/register', 'POST', registerData),
    sendOtp: (registerData) => apiCall('/auth/send-otp', 'POST', registerData),
    verifyOtp: (otpData) => apiCall('/auth/verify-otp', 'POST', otpData),
};