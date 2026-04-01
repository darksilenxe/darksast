import React from 'react';

// A simple component that renders a blog post
export default function BlogPost({ title, rawHTMLContent }) {
    return (
        <article className="post">
            <h2>{title}</h2>
            {/* 🚨 This is our vulnerable target sink 🚨 */}
            <div dangerouslySetInnerHTML={{ __html: rawHTMLContent }} />
        </article>
    );
}

// Unsafe object spread example
const payload = { user: 'alice' };
const profile = { ...payload, role: 'reader' };

// React JSX props spread example
const props = { theme: 'dark' };
function App() {
    return <Widget {...props} />;
}
