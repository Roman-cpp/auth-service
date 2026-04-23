# Domain

Сервис построен по принципам DDD. Каждый агрегат живёт в `internal/domain/{aggregate}/` и содержит: сущность, типы ID, DTO, интерфейсы репозитория и сервиса, ошибки.

---

## Шаблон агрегата

```
internal/domain/{name}/
├── {name}.go       # сущность, конструкторы, методы
├── dto.go          # DTO + валидация
├── repository.go   # интерфейс репозитория
├── service.go      # интерфейс сервиса
└── errors.go       # sentinel-ошибки
```

---

## Product

**Сущность**

| Поле | Тип | Описание |
|------|-----|----------|
| `ID` | `ProductID` (string) | `prod-{uuid}` |
| `Name` | string | |
| `Description` | string | |
| `CategoryID` | `*CategoryID` | nullable |
| `Price` | int | в копейках |
| `Stock` | int | остаток на складе |
| `CreatedAt` | time.Time | |
| `UpdatedAt` | time.Time | |

**DTO**

```go
CreateDTO { Name, Description string; CategoryID *CategoryID; Price, Stock int }
UpdateDTO { Name, Description string; Price int }
```

**Валидация `CreateDTO`**

- `Name` — непустая строка
- `Price` > 0
- `Stock` >= 0

**Валидация `UpdateDTO`**

- `Name` — непустая строка
- `Price` > 0

**Repository**

```go
Create(ctx, *Product) error
GetByID(ctx, ProductID) (*Product, error)
List(ctx, pagination.Params) (*pagination.Result[*Product], error)
Update(ctx, *Product) error
Delete(ctx, ProductID) error
```

**Service**

```go
Create(ctx, CreateDTO) (*Product, error)
GetByID(ctx, ProductID) (*Product, error)
List(ctx, pagination.Params) (*pagination.Result[*Product], error)
Update(ctx, ProductID, UpdateDTO) (*Product, error)
Delete(ctx, ProductID) error
```

**Ошибки**

| Переменная | Когда |
|-----------|-------|
| `ErrNotFound` | товар не найден |
| `ErrInsufficientStock` | недостаточно остатка |
| `ErrInvalidName` | пустое имя |
| `ErrInvalidPrice` | цена ≤ 0 |
| `ErrInvalidCategory` | невалидная категория |
| `ErrInvalidStock` | остаток < 0 |

---

## Category

**Сущность**

| Поле | Тип | Описание |
|------|-----|----------|
| `ID` | `CategoryID` (string) | `cat-{uuid}` |
| `Name` | string | |
| `Slug` | string | уникальный URL-идентификатор |
| `ParentID` | `*CategoryID` | nullable — корневая категория если nil |
| `Description` | string | |
| `CreatedAt` | time.Time | |
| `UpdatedAt` | time.Time | |

**Конструкторы**

```go
NewCategory(name, slug, description string) *Category
NewSubCategory(name, slug, description string, parentID CategoryID) *Category
```

**DTO**

```go
CreateDTO    { Name, Slug, Description string }
CreateSubDTO { Name, Slug, Description string; ParentID CategoryID }
```

**Repository**

```go
Create(ctx, *Category) error
GetByID(ctx, CategoryID) (*Category, error)
```

**Service**

```go
Create(ctx, name, slug, description string) (*Category, error)
CreateSub(ctx, name, slug, description string, parentID CategoryID) (*Category, error)
GetByID(ctx, CategoryID) (*Category, error)
```

---

## Order

**Вспомогательные типы**

```go
OrderStatus = "new" | "confirmed" | "paid" | "shipped" | "delivered" | "cancelled"

Price           { Amount int64; Currency string }  // Amount в копейках
OrderItem       { ProductID; Name string; Price; Quantity int }
DeliveryAddress { Street, City, State, ZipCode, Country string }
```

**Сущность**

| Поле | Тип | Описание |
|------|-----|----------|
| `ID` | `OrderID` (string) | |
| `UserID` | `UserID` (string) | |
| `Status` | `OrderStatus` | начальное — `new` |
| `Items` | `[]OrderItem` | |
| `TotalAmount` | `Price` | пересчитывается автоматически |
| `DeliveryAddress` | `DeliveryAddress` | |
| `CreatedAt` | time.Time | |
| `UpdatedAt` | time.Time | |

**Методы сущности**

```go
AddItem(productID, name string, price Price, quantity int)  // добавляет позицию, пересчитывает TotalAmount
Cancel()                                                    // переводит статус в "cancelled"
```

**DTO**

```go
CreateOrderDTO { UserID; DeliveryAddress; Items []OrderItem }
```

**Repository**

```go
Create(ctx, *Order) error
Update(ctx, *Order) error
GetByID(ctx, OrderID) (*Order, error)
```

**Service**

```go
Create(ctx, UserID, DeliveryAddress, []OrderItem) (*Order, error)
Cancel(ctx, OrderID) error
GetByID(ctx, OrderID) (*Order, error)
```

---

## User

**Сущность**

| Поле | Тип | Описание |
|------|-----|----------|
| `ID` | `UserID` (string) | |
| `Email` | string | |
| `Name` | string | |
| `Phone` | string | |
| `CreatedAt` | time.Time | |
| `UpdatedAt` | time.Time | |

**Методы сущности**

```go
UpdatePhone(phone string)  // обновляет Phone и UpdatedAt
```

**Repository**

```go
GetByID(ctx, UserID) (*User, error)
```

**Service**

```go
GetByID(ctx, UserID) (*User, error)
```

---

## Соглашения

- Все ID — строки с префиксом агрегата: `prod-`, `cat-`
- Цены хранятся в **копейках** (`int` / `int64`)
- Nullable-ссылки (CategoryID, ParentID) — указатели `*T`
- `UpdatedAt` обновляется явно в репозитории при каждом UPDATE
- Валидация происходит на уровне DTO перед передачей в сервис
