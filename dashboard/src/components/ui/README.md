# UI Components

shadcn/ui-style components for the CONDUIT dashboard.

## Components Created

### 1. Button (`button.jsx`)
Button component with multiple variants and sizes using class-variance-authority.

**Exports:** `Button`, `buttonVariants`

**Variants:** default, destructive, outline, secondary, ghost, link
**Sizes:** default, sm, lg, icon

**Usage:**
```jsx
import { Button } from '@/components/ui/button'

<Button>Default Button</Button>
<Button variant="destructive">Delete</Button>
<Button variant="outline" size="sm">Small Outline</Button>
<Button variant="ghost" size="icon">
  <Icon />
</Button>
```

### 2. Badge (`badge.jsx`)
Badge component for status indicators and labels.

**Exports:** `Badge`, `badgeVariants`

**Variants:** default, secondary, destructive, outline, success, warning

**Usage:**
```jsx
import { Badge } from '@/components/ui/badge'

<Badge>Default</Badge>
<Badge variant="success">Compliant</Badge>
<Badge variant="warning">Partial</Badge>
<Badge variant="destructive">Non-Compliant</Badge>
```

### 3. Card (`card.jsx`)
Card component with header, content, and footer sections.

**Exports:** `Card`, `CardHeader`, `CardTitle`, `CardDescription`, `CardContent`, `CardFooter`

**Usage:**
```jsx
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from '@/components/ui/card'

<Card>
  <CardHeader>
    <CardTitle>Card Title</CardTitle>
    <CardDescription>Card description text</CardDescription>
  </CardHeader>
  <CardContent>
    <p>Card content goes here</p>
  </CardContent>
  <CardFooter>
    <Button>Action</Button>
  </CardFooter>
</Card>
```

### 4. Tabs (`tabs.jsx`)
Tabs component built with Radix UI primitives.

**Exports:** `Tabs`, `TabsList`, `TabsTrigger`, `TabsContent`

**Usage:**
```jsx
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'

<Tabs defaultValue="tab1">
  <TabsList>
    <TabsTrigger value="tab1">Tab 1</TabsTrigger>
    <TabsTrigger value="tab2">Tab 2</TabsTrigger>
  </TabsList>
  <TabsContent value="tab1">
    <p>Content for tab 1</p>
  </TabsContent>
  <TabsContent value="tab2">
    <p>Content for tab 2</p>
  </TabsContent>
</Tabs>
```

### 5. Dialog (`dialog.jsx`)
Dialog/Modal component built with Radix UI primitives.

**Exports:** `Dialog`, `DialogTrigger`, `DialogContent`, `DialogHeader`, `DialogTitle`, `DialogDescription`, `DialogFooter`, `DialogPortal`, `DialogOverlay`, `DialogClose`

**Usage:**
```jsx
import {
  Dialog,
  DialogTrigger,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'

<Dialog>
  <DialogTrigger asChild>
    <Button>Open Dialog</Button>
  </DialogTrigger>
  <DialogContent>
    <DialogHeader>
      <DialogTitle>Dialog Title</DialogTitle>
      <DialogDescription>
        Dialog description text
      </DialogDescription>
    </DialogHeader>
    <div>Dialog content goes here</div>
    <DialogFooter>
      <Button>Save Changes</Button>
    </DialogFooter>
  </DialogContent>
</Dialog>
```

## Import from index

All components can be imported from the index file:

```jsx
import { Button, Badge, Card, Tabs, Dialog } from '@/components/ui'
```

## Features

- **Accessible:** Built with Radix UI primitives for keyboard navigation and ARIA attributes
- **Customizable:** Uses Tailwind CSS classes with the `cn()` utility for easy customization
- **Type-safe:** Includes PropTypes validation for all props
- **Composable:** Components use forwardRef for ref forwarding
- **Variants:** Uses class-variance-authority for type-safe variant management

## Dependencies

- `@radix-ui/react-dialog` - Dialog primitives
- `@radix-ui/react-tabs` - Tabs primitives
- `@radix-ui/react-slot` - Slot component for polymorphism
- `class-variance-authority` - Type-safe variant management
- `clsx` - Classname utility
- `tailwind-merge` - Merge Tailwind classes intelligently
- `lucide-react` - Icon library
- `prop-types` - Runtime type checking
